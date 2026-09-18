import re
from typing import Optional

# Comprehensive curated mapping of common MAC Organizationally Unique Identifiers (OUIs)
OUI_DATABASE = {
    # Apple
    "00:17:F2": "Apple, Inc.",
    "00:1E:52": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "04:0C:CE": "Apple, Inc.",
    "04:54:53": "Apple, Inc.",
    "18:65:90": "Apple, Inc.",
    "3C:06:30": "Apple, Inc.",
    "40:6C:8F": "Apple, Inc.",
    "60:03:08": "Apple, Inc.",
    "AC:BC:32": "Apple, Inc.",
    "DC:A9:04": "Apple, Inc.",
    "F0:18:98": "Apple, Inc.",
    "F8:FF:C2": "Apple, Inc.",
    
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading Ltd",
    "E4:5F:01": "Raspberry Pi Trading Ltd",
    "28:CD:C1": "Raspberry Pi Ltd",

    # Intel
    "00:1B:21": "Intel Corporate",
    "00:21:6A": "Intel Corporate",
    "3C:FD:FE": "Intel Corporate",
    "68:05:CA": "Intel Corporate",
    "80:86:F2": "Intel Corporate",
    "A4:4C:C8": "Intel Corporate",
    "C8:F7:50": "Intel Corporate",

    # Microsoft
    "00:15:5D": "Microsoft Corporation (Hyper-V)",
    "28:18:78": "Microsoft Corporation",
    "58:82:A8": "Microsoft Corporation",
    "7C:ED:8D": "Microsoft Corporation",
    "DC:98:40": "Microsoft Corporation",

    # Dell & HP
    "00:14:22": "Dell Inc.",
    "18:03:73": "Dell Inc.",
    "4C:D9:8F": "Dell Inc.",
    "F8:DB:88": "Dell Inc.",
    "00:25:B3": "Hewlett Packard Enterprise",
    "10:1F:74": "HP Inc.",
    "3C:D9:2B": "HP Inc.",
    "9C:8E:99": "HP Inc.",

    # Networking Gear (Cisco, TP-Link, Netgear, D-Link, Ubiquiti, MikroTik)
    "00:40:96": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "50:06:04": "Cisco Systems",
    "00:14:78": "TP-Link Technologies",
    "14:EB:B6": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "70:4F:57": "TP-Link Technologies",
    "E8:48:B8": "TP-Link Technologies",
    "00:1F:33": "Netgear Inc.",
    "20:E5:2A": "Netgear Inc.",
    "A0:04:60": "Netgear Inc.",
    "00:18:E7": "D-Link International",
    "00:27:22": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "F4:92:BF": "Ubiquiti Networks",
    "00:0C:42": "MikroTik",
    "64:D1:54": "MikroTik",

    # IoT / Espressif / Tuya / Sonoff
    "24:0A:C4": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "3C:61:05": "Espressif Inc.",
    "84:F3:EB": "Espressif Inc.",
    "A4:CF:12": "Espressif Inc.",
    "EC:FA:BC": "Espressif Inc.",

    # Samsung, Google, Sony, LG
    "00:12:47": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "50:85:69": "Samsung Electronics",
    "00:1A:11": "Google, Inc.",
    "3C:5A:B4": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "00:13:A9": "Sony Corporation",
    "FC:0F:E6": "Sony Interactive Entertainment",
    "00:1C:62": "LG Electronics",
    "CC:2D:83": "LG Electronics",

    # Virtualization (VMware, VirtualBox, QEMU, Docker)
    "00:05:69": "VMware, Inc.",
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM Virtual Machine",
    "02:42:AC": "Docker Container",
}

_cache = {}


def normalize_mac(mac: str) -> Optional[str]:
    """Clean and normalize MAC address to uppercase colon-separated format: AA:BB:CC:DD:EE:FF."""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))


def lookup_vendor(mac: str) -> str:
    """Look up the hardware manufacturer name for a given MAC address."""
    normalized = normalize_mac(mac)
    if not normalized:
        return "Unknown Device"

    if normalized in _cache:
        return _cache[normalized]

    # Check prefix (first 3 octets)
    prefix = normalized[:8]
    vendor = OUI_DATABASE.get(prefix)

    if not vendor:
        # Check locally administered or multicast bit
        first_byte = int(normalized[:2], 16)
        if first_byte & 0x02:
            vendor = "Randomized / Private MAC Address"
        else:
            vendor = "Unknown Manufacturer"

    _cache[normalized] = vendor
    return vendor
