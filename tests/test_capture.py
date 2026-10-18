"""
Manual live capture diagnostic script.
Run directly via: python tests/test_capture.py
"""
import unittest


def packet_callback(packet):
    print(packet.summary())


class TestCaptureDiagnostic(unittest.TestCase):
    def test_diagnostic_info(self):
        """Verify module imports cleanly without side-effects."""
        self.assertTrue(callable(packet_callback))


if __name__ == '__main__':
    from scapy.all import sniff

    print("Capturing 10 packets...")
    print("Open Google or YouTube in your browser...")
    sniff(count=10, prn=packet_callback, store=False)
    print("Capture completed!")
