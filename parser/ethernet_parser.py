from scapy.all import Ether
from utils.logger import setup_logger
from utils.helpers import mac_to_str

logger = setup_logger('ethernet_parser')


class EthernetParser:
    """Parse Ethernet frames"""
    
    @staticmethod
    def parse(packet):
        try:
            if packet is None or not packet.haslayer(Ether):
                return None
            
            eth = packet[Ether]
            
            result = {
                'src_mac': mac_to_str(eth.src),
                'dst_mac': mac_to_str(eth.dst),
                'type': eth.type,
                'payload_length': len(eth.payload)
            }
            
            return result
        except Exception as e:
            logger.error(f"Ethernet parse error: {e}")
            return None