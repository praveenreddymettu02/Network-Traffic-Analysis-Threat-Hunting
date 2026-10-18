"""
Scapy interface and sniffing diagnostic.
Run directly via: python tests/test_scapy.py
"""
import unittest


class TestScapyDiagnostic(unittest.TestCase):
    def test_scapy_installed(self):
        """Verify Scapy is installed and can list interfaces."""
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            self.assertIsInstance(interfaces, list)
        except ImportError:
            self.fail("Scapy is not installed")


if __name__ == '__main__':
    from scapy.all import sniff, get_if_list

    def packet_callback(pkt):
        print(pkt.summary())

    print("=" * 60)
    print("SCAPY CAPTURE TEST")
    print("=" * 60)

    # Show available interfaces
    print("\nAvailable interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"  {i}: {iface}")

    print("\n" + "=" * 60)
    print("Testing capture on auto-detected interface")
    print("Waiting for packets... (timeout 15 seconds)")
    print("=" * 60)

    try:
        sniff(prn=packet_callback, count=10, timeout=15)
        print("\n[OK] Capture test completed!")
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
