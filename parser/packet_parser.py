import time
from scapy.all import TCP, UDP, ICMP, ARP, DNS
from utils.logger import setup_logger
from parser.ethernet_parser import EthernetParser
from parser.arp_parser import ARPParser
from parser.ip_parser import IPParser
from parser.tcp_parser import TCPParser
from parser.udp_parser import UDPParser
from parser.icmp_parser import ICMPParser
from parser.dns_parser import DNSParser
from parser.http_parser import HTTPParser
from parser.tls_parser import TLSParser

logger = setup_logger('packet_parser')


class PacketParser:
    """Master packet parser - routes to appropriate protocol parsers"""
    
    def __init__(self):
        self.ethernet = EthernetParser()
        self.arp = ARPParser()
        self.ip = IPParser()
        self.tcp = TCPParser()
        self.udp = UDPParser()
        self.icmp = ICMPParser()
        self.dns = DNSParser()
        self.http = HTTPParser()
        self.tls = TLSParser()
    
    @staticmethod
    def _flatten(result):
        """Flatten protocol fields to top-level keys for DB insert."""
        flat = dict(result)

        eth = result.get('ethernet')
        if eth:
            flat.setdefault('src_mac', eth.get('src_mac'))
            flat.setdefault('dst_mac', eth.get('dst_mac'))

        ip = result.get('ip')
        if ip:
            flat.setdefault('src_ip', ip.get('src_ip'))
            flat.setdefault('dst_ip', ip.get('dst_ip'))
            flat.setdefault('ttl', ip.get('ttl'))
            flat.setdefault('length', ip.get('length'))

        arp = result.get('arp')
        if arp:
            flat.setdefault('src_ip', arp.get('src_ip'))
            flat.setdefault('dst_ip', arp.get('dst_ip'))
            flat.setdefault('src_mac', arp.get('src_mac'))
            flat.setdefault('dst_mac', arp.get('dst_mac'))

        tcp = result.get('tcp')
        if tcp:
            flat.setdefault('src_port', tcp.get('src_port'))
            flat.setdefault('dst_port', tcp.get('dst_port'))
            flat.setdefault('tcp_flags', tcp.get('flags'))

        udp = result.get('udp')
        if udp:
            flat.setdefault('src_port', udp.get('src_port'))
            flat.setdefault('dst_port', udp.get('dst_port'))

        # DNS rides on UDP/TCP - ensure ports are exposed at top level
        if flat.get('src_port') is None:
            dns = result.get('dns')
            if dns:
                flat.setdefault('src_port', dns.get('src_port'))
                flat.setdefault('dst_port', dns.get('dst_port'))

        # Store raw packet bytes
        raw_pkt = result.get('raw')
        if raw_pkt:
            try:
                flat['raw_data'] = bytes(raw_pkt)
            except Exception:
                pass

        return flat

    def parse(self, packet):
        try:
            if packet is None:
                return None

            # Use the packet's actual wire timestamp, not current wall-clock
            timestamp = int(getattr(packet, 'time', time.time()))
            
            result = {
                'timestamp': timestamp,
                'length': len(packet),
                'raw': packet
            }
            
            # Parse Ethernet
            eth = self.ethernet.parse(packet)
            if eth:
                result['ethernet'] = eth
            
            # Check ARP
            if ARP in packet:
                arp_info = self.arp.parse(packet)
                if arp_info:
                    result['protocol'] = 'ARP'
                    result['arp'] = arp_info
                    return self._flatten(result)
            
            # Parse IP
            ip_info = self.ip.parse(packet)
            if ip_info:
                result['ip'] = ip_info
                
                # Check DNS (highest priority)
                if DNS in packet:
                    dns_info = self.dns.parse(packet)
                    if dns_info:
                        result['protocol'] = 'DNS'
                        result['dns'] = dns_info
                        # DNS rides on UDP (or TCP) - capture ports
                        if UDP in packet:
                            udp_info = self.udp.parse(packet)
                            if udp_info:
                                result['udp'] = udp_info
                        elif TCP in packet:
                            tcp_info = self.tcp.parse(packet)
                            if tcp_info:
                                result['tcp'] = tcp_info
                        return self._flatten(result)
                
                # TCP
                if TCP in packet:
                    tcp_info = self.tcp.parse(packet)
                    if tcp_info:
                        result['protocol'] = 'TCP'
                        result['tcp'] = tcp_info
                        
                        # Check HTTP
                        http_info = self.http.parse(packet)
                        if http_info:
                            result['protocol'] = 'HTTP'
                            result['http'] = http_info
                            return self._flatten(result)
                        
                        # Check TLS
                        tls_info = self.tls.parse(packet)
                        if tls_info:
                            result['protocol'] = 'TLS'
                            result['tls'] = tls_info
                            return self._flatten(result)
                        
                        return self._flatten(result)
                
                # UDP
                elif UDP in packet:
                    udp_info = self.udp.parse(packet)
                    if udp_info:
                        result['protocol'] = 'UDP'
                        result['udp'] = udp_info
                        
                        # DNS detection
                        if DNS in packet:
                            dns_info = self.dns.parse(packet)
                            if dns_info:
                                result['protocol'] = 'DNS'
                                result['dns'] = dns_info
                        
                        return self._flatten(result)
                
                # ICMP
                elif ICMP in packet:
                    icmp_info = self.icmp.parse(packet)
                    if icmp_info:
                        result['protocol'] = 'ICMP'
                        result['icmp'] = icmp_info
                        return self._flatten(result)
            
            return self._flatten(result)
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return None
