import os
import re
import sys
import time
import socket
import logging
import subprocess
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger("netsentry-client.monitor")


class ActivityMonitor:
    """
    Monitors endpoint web activities, active browser network connections,
    system DNS resolution cache, and VPN adapter states.
    """

    KNOWN_BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "safari.exe"}
    VPN_KEYWORDS = ["wintun", "wireguard", "tap-windows", "tap0901", "nordlynx", "openvpn", "proton", "tailscale", "mullvad"]

    def __init__(self):
        self._seen_domains: Set[str] = set()
        self._last_dns_check = 0

    def detect_active_vpn_adapters(self) -> List[Dict[str, str]]:
        """
        Detects active VPN tunnel interfaces (e.g., WireGuard, TAP, Wintun, NordLynx).
        Returns list of detected VPN adapter dicts.
        """
        detected = []
        if sys.platform != "win32":
            return detected

        try:
            # Use netsh to query network interfaces
            proc = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            output = proc.stdout.lower()
            for line in output.splitlines():
                if "connected" in line:
                    for vpn_kw in self.VPN_KEYWORDS:
                        if vpn_kw in line:
                            detected.append({"adapter": line.strip(), "keyword": vpn_kw})
                            break
        except Exception as e:
            logger.debug(f"Error querying VPN adapters: {e}")

        return detected

    def inspect_dns_cache(self) -> List[str]:
        """
        Extracts recently resolved hostnames from the Windows DNS client cache.
        This captures domains visited by modern browsers (including those over TLS/HTTPS).
        """
        new_domains = []
        if sys.platform != "win32":
            return new_domains

        try:
            # Run ipconfig /displaydns or powershell Get-DnsClientCache
            proc = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            output = proc.stdout

            # Match "Record Name . . . . . : <domain>"
            matches = re.findall(r"Record Name\s*[\.:]+\s*([a-zA-Z0-9\.\-_]+)", output)
            for m in matches:
                dom = m.strip().lower().rstrip(".")
                # Filter out noise, localhost, local subnets, in-addr.arpa
                if (
                    len(dom) > 3
                    and "." in dom
                    and not dom.endswith(".arpa")
                    and not dom.endswith(".local")
                    and not dom.startswith("127.")
                    and not dom.startswith("192.168.")
                    and not dom.startswith("10.")
                    and dom not in self._seen_domains
                ):
                    self._seen_domains.add(dom)
                    new_domains.append(dom)

            # Limit memory footprint of seen cache
            if len(self._seen_domains) > 2000:
                self._seen_domains = set(list(self._seen_domains)[-500:])

        except Exception as e:
            logger.debug(f"Error querying DNS cache: {e}")

        return new_domains

    def sample_active_connections(self) -> List[Dict[str, Any]]:
        """
        Samples active TCP connections using netstat to identify foreign endpoints.
        """
        connections = []
        try:
            proc = subprocess.run(
                ["netstat", "-n", "-o"],
                capture_output=True,
                text=True,
                timeout=4,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0].upper() in ("TCP", "UDP") and ("ESTABLISHED" in line.upper() or parts[0].upper() == "UDP"):
                    foreign = parts[2]
                    if ":" in foreign:
                        remote_ip, _, port = foreign.rpartition(":")
                        if remote_ip not in ("127.0.0.1", "0.0.0.0", "*", "[::1]") and not remote_ip.startswith("192.168.") and not remote_ip.startswith("10."):
                            connections.append({
                                "remote_ip": remote_ip,
                                "port": port,
                                "pid": parts[-1] if len(parts) >= 5 else None
                            })
        except Exception as e:
            logger.debug(f"Error running netstat: {e}")

        return connections[:25]
