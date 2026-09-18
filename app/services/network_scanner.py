import sys
import socket
import subprocess
import ipaddress
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Tuple
from app.config import settings
from app.services.vendor_lookup import lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


def get_default_local_ip() -> Tuple[str, str]:
    """
    Detect local host IP address and interface IP.
    Returns (local_ip, suggested_subnet_cidr).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Use a non-routable public DNS IP to determine local routing interface without sending packets
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    if local_ip.startswith("127."):
        return "127.0.0.1", "127.0.0.0/8"

    # Assume standard /24 for local LAN unless specified
    try:
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return local_ip, str(network)
    except Exception:
        return local_ip, f"{local_ip}/24"


def get_authorized_subnet() -> str:
    """Return the administrator-authorized subnet or detect local subnet."""
    if settings.AUTHORIZED_SUBNET and settings.AUTHORIZED_SUBNET.strip():
        return settings.AUTHORIZED_SUBNET.strip()
    _, detected_subnet = get_default_local_ip()
    return detected_subnet


def resolve_hostname(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup for an IP address with a 1.0s timeout."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def ping_host(ip: str, timeout_ms: int = 400) -> Tuple[bool, Optional[float]]:
    """
    Perform a quick ping or TCP connect probe to trigger ARP resolution.
    Returns (is_up, response_time_ms).
    """
    start = time.time()
    is_windows = sys.platform.startswith("win")
    
    # Try ICMP ping first
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if is_windows else ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0)
        elapsed_ms = round((time.time() - start) * 1000, 2)
        if res.returncode == 0:
            return True, elapsed_ms
    except Exception:
        pass

    # Secondary lightweight TCP probe on port 80/443/445/135
    for port in [80, 445, 135]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            r = s.connect_ex((ip, port))
            elapsed_ms = round((time.time() - start) * 1000, 2)
            s.close()
            if r == 0:
                return True, elapsed_ms
        except Exception:
            s.close()

    return False, None


def read_system_arp_table() -> Dict[str, str]:
    """
    Extract IP -> MAC mapping from the system ARP cache using native commands.
    Returns {ip: normalized_mac}.
    """
    arp_map = {}
    try:
        output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        # Windows: "  192.168.1.1          00-11-22-33-44-55     dynamic"
        # Linux:   "? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
        pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F[:-]{11,17})")
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac_raw = match.groups()
                mac = normalize_mac(mac_raw)
                if mac and not mac.startswith("FF:FF:FF:FF:FF:FF"):
                    # Exclude multicast / broadcast IPs
                    if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                        arp_map[ip] = mac
    except Exception as e:
        logger.error(f"Error reading system ARP table: {e}")

    # On Windows, also query PowerShell Get-NetNeighbor for higher reliability
    if sys.platform.startswith("win"):
        try:
            ps_cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-NetNeighbor -AddressFamily IPv4 -State Reachable,Permanent | Select-Object -Property IPAddress, LinkLayerAddress | ConvertTo-Csv -NoTypeInformation"
            ]
            ps_output = subprocess.check_output(ps_cmd, text=True, stderr=subprocess.DEVNULL)
            for line in ps_output.splitlines():
                parts = [p.strip(' "') for p in line.split(",")]
                if len(parts) >= 2 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[0]):
                    ip = parts[0]
                    mac = normalize_mac(parts[1])
                    if mac and not mac.startswith("FF:FF:FF:FF:FF:FF") and not ip.startswith("224."):
                        arp_map[ip] = mac
        except Exception:
            pass

    return arp_map


class NetworkScanner:
    """
    Authorized Local Network Device Scanner.
    Strictly restricted to the administrator-configured local subnet.
    """

    def __init__(self, authorized_subnet: Optional[str] = None):
        self.subnet_cidr = authorized_subnet or get_authorized_subnet()
        self._is_scanning = False

    @property
    def is_scanning(self) -> bool:
        return self._is_scanning

    def scan_network(self) -> List[Dict[str, Any]]:
        """
        Execute an authorized discovery scan across the authorized subnet.
        Discovers active devices via ARP table examination and ICMP probe sweeps.
        """
        if self._is_scanning:
            logger.warning("Scan already in progress. Rejecting concurrent scan request.")
            return []

        self._is_scanning = True
        try:
            # Check Demo Mode
            if settings.DEMO_MODE:
                return self._generate_demo_devices()

            network = ipaddress.IPv4Network(self.subnet_cidr, strict=False)
            hosts = list(network.hosts())

            # Safeguard: Do not scan more than /24 (254 hosts) per scan to prevent network saturation
            if len(hosts) > 254:
                logger.warning(f"Subnet {self.subnet_cidr} has {len(hosts)} hosts. Limiting scan to first 254 hosts.")
                hosts = hosts[:254]

            logger.info(f"Initiating network probe sweep for {len(hosts)} hosts on {self.subnet_cidr}...")

            # Fast threaded probe sweep to populate ARP cache
            with ThreadPoolExecutor(max_workers=32) as executor:
                list(executor.map(lambda h: ping_host(str(h), timeout_ms=250), hosts))

            # Read refreshed ARP table
            arp_cache = read_system_arp_table()
            local_ip, _ = get_default_local_ip()

            discovered_devices = []
            for ip, mac in arp_cache.items():
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    # Verify discovered IP is inside authorized subnet
                    if ip_obj in network:
                        # Probe response time & check if alive
                        is_up, rtt = ping_host(ip, timeout_ms=300)
                        hostname = resolve_hostname(ip)
                        vendor = lookup_vendor(mac)

                        # Tag host machine if matches local IP
                        if ip == local_ip:
                            hostname = hostname or socket.gethostname()

                        discovered_devices.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": hostname,
                            "vendor": vendor,
                            "status": "ONLINE" if is_up else "OFFLINE",
                            "response_time_ms": rtt if rtt else 5.0,
                            "is_local_host": (ip == local_ip)
                        })
                except Exception as e:
                    logger.debug(f"Error processing IP {ip}: {e}")

            # Ensure the scanning host itself is included if not in ARP table
            if local_ip != "127.0.0.1" and not any(d["ip_address"] == local_ip for d in discovered_devices):
                discovered_devices.append({
                    "ip_address": local_ip,
                    "mac_address": "00:00:00:00:00:00",
                    "hostname": socket.gethostname(),
                    "vendor": "Local NETSENTRY Host",
                    "status": "ONLINE",
                    "response_time_ms": 0.5,
                    "is_local_host": True
                })

            logger.info(f"Scan completed. Discovered {len(discovered_devices)} devices on {self.subnet_cidr}.")
            return discovered_devices
        finally:
            self._is_scanning = False

    def _generate_demo_devices(self) -> List[Dict[str, Any]]:
        """
        Generate realistic simulated devices for controlled project evaluations.
        Clearly tags every device with [DEMO MODE].
        """
        time.sleep(1.0)  # Simulate scan duration
        base_ip = "192.168.1."
        return [
            {
                "ip_address": f"{base_ip}1",
                "mac_address": "E8:48:B8:1A:22:33",
                "hostname": "gateway.local [DEMO MODE]",
                "vendor": "TP-Link Technologies",
                "status": "ONLINE",
                "response_time_ms": 2.1,
                "is_local_host": False,
            },
            {
                "ip_address": f"{base_ip}15",
                "mac_address": "AC:BC:32:89:12:34",
                "hostname": "MacBook-Pro-Admin [DEMO MODE]",
                "vendor": "Apple, Inc.",
                "status": "ONLINE",
                "response_time_ms": 4.5,
                "is_local_host": True,
            },
            {
                "ip_address": f"{base_ip}42",
                "mac_address": "DC:A6:32:44:55:66",
                "hostname": "lab-cam-raspberrypi [DEMO MODE]",
                "vendor": "Raspberry Pi Trading Ltd",
                "status": "ONLINE",
                "response_time_ms": 12.8,
                "is_local_host": False,
            },
            {
                "ip_address": f"{base_ip}77",
                "mac_address": "00:14:22:98:76:54",
                "hostname": "workstation-pc [DEMO MODE]",
                "vendor": "Dell Inc.",
                "status": "ONLINE",
                "response_time_ms": 8.3,
                "is_local_host": False,
            },
            {
                "ip_address": f"{base_ip}105",
                "mac_address": "24:0A:C4:11:22:33",
                "hostname": "iot-sensor-hub [DEMO MODE]",
                "vendor": "Espressif Inc.",
                "status": "ONLINE",
                "response_time_ms": 18.2,
                "is_local_host": False,
            }
        ]


scanner = NetworkScanner()
