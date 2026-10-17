from scapy.all import ICMP
from utils.logger import setup_logger

logger = setup_logger('icmp_parser')

class ICMPParser:
    """Parse ICMP packets"""
    
    ICMP_TYPES = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        4: 'Source Quench',
        5: 'Redirect',
        8: 'Echo Request',
        9: 'Router Advertisement',
        10: 'Router Solicitation',
        11: 'Time Exceeded',
        12: 'Parameter Problem',
        13: 'Timestamp Request',
        14: 'Timestamp Reply',
        15: 'Information Request',
        16: 'Information Reply',
        17: 'Address Mask Request',
        18: 'Address Mask Reply'
    }
    
    @staticmethod
    def parse(packet):
        try:
            if not packet.haslayer(ICMP):
                return None
            
            icmp = packet[ICMP]
            
            result = {
                'type': icmp.type,
                'type_name': ICMPParser.ICMP_TYPES.get(icmp.type, f'Unknown ({icmp.type})'),
                'code': icmp.code,
                'checksum': icmp.chksum
            }
            
            # Echo specific fields
            if icmp.type in [0, 8]:
                result['echo_id'] = icmp.id if hasattr(icmp, 'id') else None
                result['echo_seq'] = icmp.seq if hasattr(icmp, 'seq') else None
            
            return result
        except Exception as e:
            logger.error(f"ICMP parse error: {e}")
            return None