from scapy.all import UDP
from utils.logger import setup_logger

logger = setup_logger('udp_parser')

class UDPParser:
    """Parse UDP datagrams"""
    
    @staticmethod
    def parse(packet):
        try:
            if not packet.haslayer(UDP):
                return None
            
            udp = packet[UDP]
            
            result = {
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'length': udp.len,
                'payload_length': len(udp.payload) if udp.payload else 0,
                'checksum': udp.chksum
            }
            
            return result
        except Exception as e:
            logger.error(f"UDP parse error: {e}")
            return None