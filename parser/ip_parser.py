from scapy.all import IP, IPv6
from utils.logger import setup_logger

logger = setup_logger('ip_parser')

class IPParser:
    """Parse IPv4 and IPv6 packets"""
    
    @staticmethod
    def parse(packet):
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                return {
                    'version': 4,
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'ttl': ip.ttl,
                    'protocol': ip.proto,
                    'length': ip.len,
                    'id': ip.id,
                    'flags': int(ip.flags) if hasattr(ip.flags, '__int__') else str(ip.flags),
                    'frag': ip.frag
                }
            elif packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                return {
                    'version': 6,
                    'src_ip': ip6.src,
                    'dst_ip': ip6.dst,
                    'hop_limit': ip6.hlim,
                    'next_header': ip6.nh,
                    'payload_length': ip6.plen,
                    'flow_label': ip6.fl
                }
            return None
        except Exception as e:
            logger.error(f"IP parse error: {e}")
            return None