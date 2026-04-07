#!/usr/bin/env python3
"""
ipcam_scanner.py — IP Camera Discovery & XML Export
Discovers IP cameras on the local network via ONVIF WS-Discovery and port scanning,
then exports all found device data to an XML file in ~/Downloads.

Usage:
    python3 ipcam_scanner.py [options]

Options:
    --subnet    192.168.1.0/24,10.0.0.0/24   Subnets to scan, comma-separated (default: all local interfaces)
    --timeout   1.0              Port scan connection timeout in seconds
    --output    /path/to/file    Output XML path (default: ~/Downloads/ip_cameras_<ts>.xml)
    --ports     80,554,8080      Comma-separated list of ports to scan
    --onvif-timeout 3            Seconds to wait for ONVIF WS-Discovery responses
    --workers   200              Thread pool size for port scanning
"""

import argparse
import ipaddress
import os
import re
import socket
import struct
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from xml.dom import minidom

# ANSI colors
_B = "\033[1m";  _R = "\033[0m";  _C = "\033[96m"
_G = "\033[92m"; _Y = "\033[93m"; _D = "\033[90m"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CAMERA_PORTS = [80, 443, 554, 8000, 8080, 8554, 34567, 37777]

PORT_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8554: "RTSP-ALT",
    34567: "Dahua",
    37777: "Dahua-SDK",
}

# Known camera brand signatures for HTTP banner matching
BRAND_SIGNATURES = [
    ("Hikvision",  [b"hikvision", b"HIKVISION", b"Hikvision"]),
    ("Dahua",      [b"dahua", b"DAHUA", b"DH-", b"Dahua"]),
    ("Axis",       [b"Axis", b"AXIS", b"axis-product"]),
    ("Reolink",    [b"Reolink", b"reolink"]),
    ("Amcrest",    [b"Amcrest", b"amcrest"]),
    ("Foscam",     [b"Foscam", b"foscam"]),
    ("Uniview",    [b"Uniview", b"uniview", b"UNV"]),
    ("Hanwha",     [b"Hanwha", b"hanwha", b"SNO-", b"QNO-"]),
    ("Bosch",      [b"Bosch", b"BOSCH"]),
    ("Sony",       [b"Sony", b"SONY", b"SNC-"]),
    ("Panasonic",  [b"Panasonic", b"panasonic", b"WV-"]),
    ("Vivotek",    [b"VIVOTEK", b"Vivotek"]),
    ("Pelco",      [b"Pelco", b"pelco"]),
    ("Honeywell",  [b"Honeywell", b"honeywell"]),
]

# Common RTSP stream path patterns per brand
RTSP_PATHS = {
    "Hikvision": ["/Streaming/Channels/101", "/Streaming/Channels/102"],
    "Dahua":     ["/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1"],
    "Axis":      ["/axis-media/media.amp", "/axis-media/media.amp?videocodec=h264"],
    "Reolink":   ["/h264Preview_01_main", "/h264Preview_01_sub"],
    "Foscam":    ["/videoMain", "/videoSub"],
    "_default":  ["/stream1", "/stream2", "/live/ch0", "/live/ch1", "/11", "/12"],
}

# WS-Discovery multicast address/port
WSD_MCAST_ADDR = "239.255.255.250"
WSD_MCAST_PORT = 3702

WSD_PROBE_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
    xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
    xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
    xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:{msg_id}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>"""


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_local_ip() -> str:
    """Return the primary local IP by connecting a UDP socket (no data sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def derive_subnet(local_ip: str) -> str:
    """Assume /24 subnet from the local IP."""
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_all_local_subnets() -> list:
    """
    Detect all active IPv4 subnets from every network interface using
    Linux ioctl calls (SIOCGIFADDR / SIOCGIFNETMASK). Falls back to a
    single /24 derived from the primary IP.
    /32 and /31 results (point-to-point or misconfigured interfaces) are
    widened to /24 so the full local segment gets scanned.
    Returns a deduplicated list of subnet strings, e.g. ['192.168.1.0/24', '10.0.0.0/24'].
    """
    try:
        import fcntl
        SIOCGIFADDR    = 0x8915
        SIOCGIFNETMASK = 0x891B

        subnets = []
        seen = set()
        for iface_name, _ in socket.if_nameindex():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                iface_bytes = struct.pack("256s", iface_name.encode()[:15])
                ip_raw = fcntl.ioctl(sock.fileno(), SIOCGIFADDR,    iface_bytes)[20:24]
                nm_raw = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, iface_bytes)[20:24]
                sock.close()
                ip      = socket.inet_ntoa(ip_raw)
                netmask = socket.inet_ntoa(nm_raw)
                if ip.startswith("127.") or ip == "0.0.0.0":
                    continue
                net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                # /32 and /31 = point-to-point / host route → widen to /24
                if net.prefixlen >= 31:
                    net = ipaddress.IPv4Network(derive_subnet(ip), strict=False)
                net_str = str(net)
                if net_str not in seen:
                    seen.add(net_str)
                    subnets.append(net_str)
            except Exception:
                continue
        if subnets:
            return subnets
    except Exception:
        pass
    # Fallback: single /24 from primary IP
    return [derive_subnet(get_local_ip())]


def get_mac_from_proc_arp(ip: str) -> str:
    """Read MAC address from /proc/net/arp (Linux only). Returns 'Unknown' on failure."""
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 4 and fields[0] == ip:
                    mac = fields[3]
                    if mac != "00:00:00:00:00:00":
                        return mac.upper()
    except Exception:
        pass
    return "Unknown"


def reverse_dns(ip: str) -> str:
    """Attempt reverse DNS lookup; return the IP itself on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


# ---------------------------------------------------------------------------
# ONVIF WS-Discovery
# ---------------------------------------------------------------------------

def onvif_discover(timeout: float = 3.0) -> list:
    """
    Send a WS-Discovery Probe via UDP multicast and collect responses.
    Returns a list of dicts: {ip, xaddrs, types, scopes}.
    """
    probe = WSD_PROBE_TEMPLATE.format(msg_id=str(uuid.uuid4())).encode("utf-8")
    discovered = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        sock.settimeout(timeout)
        sock.sendto(probe, (WSD_MCAST_ADDR, WSD_MCAST_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                if ip in discovered:
                    continue
                info = _parse_wsd_response(data, ip)
                if info:
                    discovered[ip] = info
            except socket.timeout:
                break
            except Exception:
                continue
    except Exception as e:
        print(f"  [ONVIF] WS-Discovery error: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return list(discovered.values())


def _parse_wsd_response(data: bytes, src_ip: str) -> dict:
    """Parse a WS-Discovery ProbeMatch XML response."""
    try:
        root = ET.fromstring(data.decode("utf-8", errors="replace"))
        ns = {
            "soap": "http://www.w3.org/2003/05/soap-envelope",
            "wsd":  "http://schemas.xmlsoap.org/ws/2005/04/discovery",
            "wsa":  "http://schemas.xmlsoap.org/ws/2004/08/addressing",
        }
        xaddrs_el = root.find(".//wsd:XAddrs", ns)
        types_el   = root.find(".//wsd:Types",  ns)
        scopes_el  = root.find(".//wsd:Scopes", ns)

        xaddrs = xaddrs_el.text.strip().split() if xaddrs_el is not None and xaddrs_el.text else []
        types  = types_el.text.strip()          if types_el  is not None and types_el.text  else ""
        scopes = scopes_el.text.strip().split() if scopes_el is not None and scopes_el.text else []

        return {
            "ip":      src_ip,
            "xaddrs":  xaddrs,
            "types":   types,
            "scopes":  scopes,
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Port scanner
# ---------------------------------------------------------------------------

def check_port(ip: str, port: int, timeout: float) -> bool:
    """Return True if the TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def scan_host_ports(ip: str, ports: list, timeout: float) -> list:
    """Return list of open ports for a single host."""
    open_ports = []
    for port in ports:
        if check_port(ip, port, timeout):
            open_ports.append(port)
    return open_ports


def scan_subnet(
    subnet: str,
    ports: list,
    timeout: float,
    workers: int,
    progress: bool = True,
) -> dict:
    """
    Scan all hosts in the subnet for the given ports.
    Returns {ip: [open_ports]} for hosts with at least one open port.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    total = len(hosts)
    results = {}

    print(f"  Scanning {total} hosts on {subnet} for ports {ports}...")

    def _scan(ip_obj):
        ip = str(ip_obj)
        open_ports = scan_host_ports(ip, ports, timeout)
        return ip, open_ports

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_scan, h): h for h in hosts}
        for fut in as_completed(futures):
            ip, open_ports = fut.result()
            done += 1
            if open_ports:
                results[ip] = open_ports
            if progress and done % 50 == 0:
                print(f"    {done}/{total} hosts checked, {len(results)} with open ports so far...")

    return results


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------

def http_probe(ip: str, port: int, timeout: float = 3.0) -> dict:
    """
    Perform a basic HTTP GET on the root path. Returns a dict with
    'server', 'body_snippet', 'manufacturer', 'model', 'firmware'.
    """
    result = {"server": "", "body_snippet": b"", "manufacturer": "", "model": "", "firmware": ""}
    scheme = "https" if port == 443 else "http"
    try:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url = f"{scheme}://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "ipcam-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["server"] = resp.headers.get("Server", "")
            result["body_snippet"] = resp.read(2048)
    except Exception:
        # Try plain HTTP even for port 443 as fallback
        try:
            import urllib.request
            url = f"http://{ip}:{port}/"
            req = urllib.request.Request(url, headers={"User-Agent": "ipcam-scanner/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result["server"] = resp.headers.get("Server", "")
                result["body_snippet"] = resp.read(2048)
        except Exception:
            pass

    # Detect manufacturer from server header + body
    probe_bytes = (result["server"].encode() + result["body_snippet"]).lower()
    for brand, sigs in BRAND_SIGNATURES:
        if any(sig.lower() in probe_bytes for sig in sigs):
            result["manufacturer"] = brand
            break

    # Try to extract model/firmware from common patterns
    body_str = result["body_snippet"].decode("utf-8", errors="replace")
    for pattern in [
        r'(?i)model["\s:>]+([A-Za-z0-9_\-]{4,30})',
        r'(?i)device\s*model["\s:>]+([A-Za-z0-9_\-]{4,30})',
    ]:
        m = re.search(pattern, body_str)
        if m:
            result["model"] = m.group(1).strip()
            break

    for pattern in [
        r'(?i)firmware["\s:>]+([A-Za-z0-9_\.\-]{4,30})',
        r'(?i)version["\s:>]+(V?\d+\.\d+[\.\d]*)',
    ]:
        m = re.search(pattern, body_str)
        if m:
            result["firmware"] = m.group(1).strip()
            break

    return result


def build_rtsp_urls(ip: str, port: int, manufacturer: str) -> list:
    """Return a list of likely RTSP stream URLs for the given camera."""
    rtsp_port = 554
    paths = RTSP_PATHS.get(manufacturer, []) + RTSP_PATHS["_default"]
    seen = set()
    urls = []
    for path in paths:
        url = f"rtsp://{ip}:{rtsp_port}{path}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:4]  # cap at 4 URLs per camera


# ---------------------------------------------------------------------------
# Serial number retrieval
# ---------------------------------------------------------------------------

def get_dahua_serial(ip: str, timeout: float = 2.0) -> str:
    """
    Try to fetch the Dahua device serial number via the CGI API.
    Returns the serial string (e.g. '3E04627PAK00077') or '' on failure.
    """
    import urllib.request

    for path in [
        "/cgi-bin/magicBox.cgi?action=getSerialNo",
        "/cgi-bin/magicBox.cgi?action=getDeviceType",
    ]:
        try:
            url = f"http://{ip}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "ipcam-scanner/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(256).decode("utf-8", errors="replace").strip()
            # Response format: "serialNo=3E04627PAK00077"
            for line in body.splitlines():
                if "=" in line:
                    key, _, val = line.partition("=")
                    val = val.strip()
                    if val and val.upper() != "UNKNOWN":
                        return val
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------------------
# Camera data assembly
# ---------------------------------------------------------------------------

def enrich_camera(ip: str, open_ports: list, timeout: float, discovery_method: str) -> dict:
    """Combine port scan + HTTP probe into a unified camera record."""
    cam = {
        "ip": ip,
        "hostname": reverse_dns(ip),
        "mac": get_mac_from_proc_arp(ip),
        "discovery_method": discovery_method,
        "open_ports": open_ports,
        "manufacturer": "",
        "model": "",
        "firmware": "",
        "serial": "",
        "streams": [],
    }

    # HTTP probe on first available web port
    for port in [p for p in open_ports if p in (80, 8080, 443, 8000)]:
        probe = http_probe(ip, port, timeout=timeout)
        if probe["manufacturer"]:
            cam["manufacturer"] = probe["manufacturer"]
        if probe["model"]:
            cam["model"] = probe["model"]
        if probe["firmware"]:
            cam["firmware"] = probe["firmware"]
        break  # one probe is enough

    # Try to get serial number via Dahua CGI (works for Dahua and some OEM cameras)
    cam["serial"] = get_dahua_serial(ip, timeout=timeout)

    # Build RTSP stream URLs
    if 554 in open_ports or 8554 in open_ports:
        cam["streams"] = build_rtsp_urls(ip, 554, cam["manufacturer"])

    return cam


# ---------------------------------------------------------------------------
# XML generation
# ---------------------------------------------------------------------------

def build_xml(cameras: list, username: str, password: str) -> str:
    """
    Build a Dahua DeviceManager XML string (version 2.0).
    Compatible with Dahua ConfigTool / SmartPSS device import.
    """
    root = ET.Element("DeviceManager")
    root.set("version", "2.0")

    for cam in cameras:
        dev = ET.SubElement(root, "Device")
        name = cam["serial"] or cam["ip"]
        # Choose port: prefer 37777 (Dahua SDK), fallback to first open port
        if 37777 in cam["open_ports"]:
            port = 37777
        elif cam["open_ports"]:
            port = cam["open_ports"][0]
        else:
            port = 37777
        dev.set("name",     name)
        dev.set("domain",   name)
        dev.set("port",     str(port))
        dev.set("username", username)
        dev.set("password", password)
        dev.set("protocol", "1")
        dev.set("connect",  "19")

    # Pretty-print via minidom, but strip the XML declaration (Dahua doesn't use one)
    raw_xml = ET.tostring(root, encoding="unicode")
    dom = minidom.parseString(raw_xml)
    lines = dom.toprettyxml(indent="  ").splitlines()
    # Remove first line (<?xml version="1.0" ?>) produced by minidom
    return "\n".join(lines[1:])


def save_xml(content: str, output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Discover IP cameras on the local network and export data to XML."
    )
    parser.add_argument("--subnet",        default="",    help="Subnet(s) to scan, comma-separated (default: all local interfaces)")
    parser.add_argument("--timeout",       type=float, default=1.0,  help="Port scan timeout in seconds (default: 1.0)")
    parser.add_argument("--output",        default="",    help="Output XML file path (default: ~/Downloads/ip_cameras_<ts>.xml)")
    parser.add_argument("--ports",         default="",    help="Comma-separated ports to scan (default: built-in list)")
    parser.add_argument("--onvif-timeout", type=float, default=3.0,  dest="onvif_timeout", help="ONVIF WS-Discovery listen timeout (default: 3.0)")
    parser.add_argument("--workers",       type=int,   default=200,  help="Thread pool size for port scanning (default: 200)")
    parser.add_argument("--no-onvif",      action="store_true",      dest="no_onvif", help="Skip ONVIF WS-Discovery")
    parser.add_argument("--no-portscan",   action="store_true",      dest="no_portscan", help="Skip port scanning (use ONVIF only)")
    parser.add_argument("--username",      default="admin",           help="Camera username written into XML (default: admin)")
    parser.add_argument("--password",      default="",                help="Dahua-encoded password string written verbatim into XML")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Interactive UI
# ---------------------------------------------------------------------------

def interactive_ui():
    """Interactive terminal menu to configure and run the scanner."""
    auto = get_all_local_subnets()
    cfg = {
        "subnet":       "",           # empty = auto
        "timeout":      1.0,
        "ports":        "",           # empty = default
        "no_onvif":     False,
        "no_portscan":  False,
        "onvif_timeout": 3.0,
        "workers":      200,
        "username":     "admin",
        "password":     "",
        "output":       "",
    }

    def _show():
        os.system("clear")
        w = 54
        subnet_disp = cfg["subnet"] or f"{_D}auto: {', '.join(auto)}{_R}"
        ports_disp  = cfg["ports"]  or f"{_D}Standard{_R}"
        onvif_disp  = f"{_D}✗ aus{_R}" if cfg["no_onvif"]    else f"{_G}✓ an{_R}"
        scan_disp   = f"{_D}✗ aus{_R}" if cfg["no_portscan"] else f"{_G}✓ an{_R}"
        out_disp    = cfg["output"] or f"{_D}~/Downloads/ip_cameras_<ts>.xml{_R}"

        print(f"\n{_B}{_C}{'─' * w}{_R}")
        print(f"{_B}{_C}  IP Camera Scanner{_R}")
        print(f"{_B}{_C}{'─' * w}{_R}\n")
        print(f"  {_Y}1{_R}  Subnets      {subnet_disp}")
        print(f"  {_Y}2{_R}  Timeout      {cfg['timeout']}s")
        print(f"  {_Y}3{_R}  Ports        {ports_disp}")
        print(f"  {_Y}4{_R}  ONVIF        {onvif_disp}")
        print(f"  {_Y}5{_R}  Port-Scan    {scan_disp}")
        print(f"  {_Y}6{_R}  Username     {cfg['username'] or _D+'(leer)'+_R}")
        print(f"  {_Y}7{_R}  Passwort     {'***' if cfg['password'] else _D+'(leer)'+_R}")
        print(f"  {_Y}8{_R}  Output       {out_disp}")
        print(f"\n{_B}{_C}{'─' * w}{_R}")
        print(f"  {_B}{_G}S{_R}  Scan starten    {_B}{_D}Q{_R}  Beenden")
        print(f"{_B}{_C}{'─' * w}{_R}\n")

    while True:
        _show()
        choice = input(f"  {_B}Auswahl:{_R} ").strip().lower()

        if choice == "q":
            print()
            return 0

        elif choice == "s":
            import argparse as _ap
            args = _ap.Namespace(
                subnet        = cfg["subnet"],
                timeout       = cfg["timeout"],
                ports         = cfg["ports"],
                no_onvif      = cfg["no_onvif"],
                no_portscan   = cfg["no_portscan"],
                onvif_timeout = cfg["onvif_timeout"],
                workers       = cfg["workers"],
                username      = cfg["username"],
                password      = cfg["password"],
                output        = cfg["output"],
            )
            _run(args)
            input(f"\n  {_D}[Enter] zurück zum Menü...{_R}")

        elif choice == "1":
            print(f"  {_D}Leer lassen für automatische Erkennung.{_R}")
            print(f"  {_D}Mehrere mit Komma trennen: 192.168.1.0/24,10.0.0.0/24{_R}")
            v = input(f"  {_Y}>{_R} Subnets: ").strip()
            cfg["subnet"] = v

        elif choice == "2":
            v = input(f"  {_Y}>{_R} Timeout in Sekunden [{cfg['timeout']}]: ").strip()
            try:
                cfg["timeout"] = float(v)
            except ValueError:
                pass

        elif choice == "3":
            print(f"  {_D}Standard: {', '.join(str(p) for p in CAMERA_PORTS)}{_R}")
            v = input(f"  {_Y}>{_R} Ports (kommagetrennt, leer = Standard): ").strip()
            cfg["ports"] = v

        elif choice == "4":
            cfg["no_onvif"] = not cfg["no_onvif"]

        elif choice == "5":
            cfg["no_portscan"] = not cfg["no_portscan"]

        elif choice == "6":
            v = input(f"  {_Y}>{_R} Username [{cfg['username']}]: ").strip()
            if v:
                cfg["username"] = v

        elif choice == "7":
            v = input(f"  {_Y}>{_R} Passwort (Dahua-kodiert): ").strip()
            cfg["password"] = v

        elif choice == "8":
            v = input(f"  {_Y}>{_R} Output-Pfad (leer = auto): ").strip()
            cfg["output"] = v


def _run(args):
    """Execute the scan pipeline from parsed args (used by both UI and CLI)."""
    subnets = [s.strip() for s in args.subnet.split(",") if s.strip()] \
              if args.subnet else get_all_local_subnets()
    ports   = [int(p.strip()) for p in args.ports.split(",") if p.strip()] \
              if args.ports else CAMERA_PORTS
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or os.path.join(
        os.path.expanduser("~/Downloads"), f"ip_cameras_{ts}.xml")
    local_ip = get_local_ip()

    print(f"\n{_B}{_C}{'═' * 54}{_R}")
    print(f"{_B}{_C}  Scan läuft...{_R}")
    print(f"{_B}{_C}{'═' * 54}{_R}")
    print(f"{_D}  Local IP : {local_ip}")
    print(f"  Subnets  : {', '.join(subnets)}{_R}")

    start_time = time.time()
    cameras = {}

    # Phase 1: ONVIF
    if not args.no_onvif:
        print(f"\n{_B}[1/2] ONVIF WS-Discovery{_R} ({args.onvif_timeout:.0f}s)...")
        for dev in onvif_discover(timeout=args.onvif_timeout):
            ip = dev["ip"]
            if ip not in cameras:
                op = scan_host_ports(ip, ports, args.timeout)
                cam = enrich_camera(ip, op, args.timeout, "ONVIF")
                for scope in dev.get("scopes", []):
                    for brand, _ in BRAND_SIGNATURES:
                        if brand.lower() in scope.lower() and not cam["manufacturer"]:
                            cam["manufacturer"] = brand
                cameras[ip] = cam
                print(f"  {_G}+{_R} {ip}  [{cam['manufacturer'] or '?'}]  ports={op}")
        print(f"  {_G}✓{_R} {len([c for c in cameras.values() if c['discovery_method']=='ONVIF'])} via ONVIF")
    else:
        print(f"\n{_D}[1/2] ONVIF übersprungen.{_R}")

    # Phase 2: Port-Scan
    if not args.no_portscan:
        for idx, subnet in enumerate(subnets, 1):
            print(f"\n{_B}[2/2] Port-Scan{_R}  {subnet}  ({idx}/{len(subnets)})...")
            new = 0
            for ip, op in scan_subnet(subnet, ports, args.timeout, args.workers).items():
                if ip not in cameras:
                    cam = enrich_camera(ip, op, args.timeout, "PortScan")
                    cameras[ip] = cam
                    new += 1
                    print(f"  {_G}+{_R} {ip}  [{cam['manufacturer'] or '?'}]  ports={op}")
            print(f"  {_G}✓{_R} {new} neue Gerät(e) auf {subnet}.")
    else:
        print(f"\n{_D}[2/2] Port-Scan übersprungen.{_R}")

    cam_list = sorted(cameras.values(), key=lambda c: socket.inet_aton(c["ip"]))
    dur = time.time() - start_time

    print(f"\n{_B}{_G}{'═' * 54}{_R}")
    print(f"{_B}{_G}  {len(cam_list)} Kamera(s) gefunden  —  {dur:.1f}s{_R}")
    print(f"{_B}{_G}{'═' * 54}{_R}")

    save_xml(build_xml(cam_list, args.username, args.password), output_path)
    print(f"\n{_G}✓ Gespeichert:{_R} {output_path}")


def main():
    if len(sys.argv) == 1:
        return interactive_ui()
    _run(parse_args())


if __name__ == "__main__":
    sys.exit(main())
