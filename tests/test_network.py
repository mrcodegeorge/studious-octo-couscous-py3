import ipaddress
from app.services.vendor_lookup import normalize_mac, lookup_vendor
from app.services.network_scanner import NetworkScanner


def test_mac_normalization():
    assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert normalize_mac("001122334455") == "00:11:22:33:44:55"
    assert normalize_mac("00:11:22:33:44:5g") is None  # Invalid hex
    assert normalize_mac("invalid") is None


def test_vendor_lookup():
    # Apple OUI
    assert "Apple" in lookup_vendor("00:17:F2:12:34:56")
    # Raspberry Pi OUI
    assert "Raspberry Pi" in lookup_vendor("B8:27:EB:AA:BB:CC")
    # TP-Link OUI
    assert "TP-Link" in lookup_vendor("E8:48:B8:11:22:33")
    # Unknown OUI
    vendor = lookup_vendor("00:00:00:11:22:33")
    assert vendor is not None


def test_subnet_validation():
    subnet = "192.168.1.0/24"
    net = ipaddress.IPv4Network(subnet, strict=False)
    assert ipaddress.IPv4Address("192.168.1.1") in net
    assert ipaddress.IPv4Address("192.168.1.254") in net
    assert ipaddress.IPv4Address("10.0.0.1") not in net


def test_demo_mode_devices():
    scanner = NetworkScanner("192.168.1.0/24")
    demo_devices = scanner._generate_demo_devices()
    assert len(demo_devices) >= 4
    for d in demo_devices:
        assert "ip_address" in d
        assert "mac_address" in d
        assert "[DEMO MODE]" in d["hostname"]
