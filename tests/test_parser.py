import unittest
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether, Raw, conf
from parser.packet_parser import PacketParser


class TestParser(unittest.TestCase):
    def setUp(self):
        conf.verb = 0
        self.parser = PacketParser()

    def test_parse_tcp(self):
        p = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb') / IP(src='1.2.3.4', dst='5.6.7.8') / TCP(sport=1234, dport=80, flags='S')
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['src_ip'], '1.2.3.4')
        self.assertEqual(res['dst_ip'], '5.6.7.8')
        self.assertEqual(res['protocol'], 'TCP')
        self.assertEqual(res['src_port'], 1234)

    def test_parse_udp(self):
        p = Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(sport=5000, dport=6000)
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['protocol'], 'UDP')
        self.assertEqual(res['src_port'], 5000)
        self.assertEqual(res['dst_port'], 6000)

    def test_parse_ipv6(self):
        p = Ether() / IPv6(src='2001:db8::1', dst='2001:db8::2') / UDP(sport=111, dport=222)
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['src_ip'], '2001:db8::1')
        self.assertEqual(res['dst_ip'], '2001:db8::2')

    def test_parse_icmp(self):
        p = Ether() / IP(src='192.168.1.1', dst='192.168.1.2') / ICMP(type=8, code=0)
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['protocol'], 'ICMP')
        self.assertIn('icmp', res)
        self.assertEqual(res['icmp']['type'], 8)

    def test_parse_arp(self):
        p = Ether() / ARP(op=1, psrc='192.168.1.10', pdst='192.168.1.1', hwsrc='00:11:22:33:44:55', hwdst='ff:ff:ff:ff:ff:ff')
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['protocol'], 'ARP')
        self.assertEqual(res['src_ip'], '192.168.1.10')
        self.assertEqual(res['dst_ip'], '192.168.1.1')

    def test_parse_dns(self):
        p = Ether() / IP(src='10.0.0.5', dst='8.8.8.8') / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname='example.com'))
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['protocol'], 'DNS')
        self.assertIn('dns', res)

    def test_parse_http(self):
        http_raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pytest\r\n\r\n"
        p = Ether() / IP(src='10.0.0.5', dst='93.184.216.34') / TCP(sport=54321, dport=80) / Raw(load=http_raw)
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['protocol'], 'HTTP')
        self.assertEqual(res['http']['method'], 'GET')
        self.assertEqual(res['http']['host'], 'example.com')

    def test_parse_tls(self):
        # Sample TLS ClientHello Record header (0x16 0x03 0x03)
        tls_raw = b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"
        p = Ether() / IP(src='10.0.0.5', dst='104.16.123.96') / TCP(sport=54322, dport=443) / Raw(load=tls_raw)
        res = self.parser.parse(p)
        self.assertIsNotNone(res)
        self.assertEqual(res['protocol'], 'TLS')

