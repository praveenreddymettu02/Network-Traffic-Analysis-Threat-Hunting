import time
from scapy.all import ARP
from utils.logger import setup_logger
from utils.helpers import mac_to_str

logger = setup_logger('arp_parser')


class ARPParser:
    """Parse ARP packets and extract detailed information"""

    @staticmethod
    def parse(packet):
        """Extract ARP information from packet"""
        try:
            if not packet.haslayer(ARP):
                return None

            arp = packet[ARP]

            arp_operations = {
                1: 'Request (Who has)',
                2: 'Reply (Is at)',
                3: 'RARP Request',
                4: 'RARP Reply'
            }

            result = {
                'timestamp': int(time.time()),
                'src_ip': arp.psrc,
                'dst_ip': arp.pdst,
                'src_mac': mac_to_str(arp.hwsrc) if arp.hwsrc else None,
                'dst_mac': mac_to_str(arp.hwdst) if arp.hwdst else None,
                'operation': arp.op,
                'operation_name': arp_operations.get(
                    arp.op, f'Unknown ({arp.op})'),
                'hw_type': arp.hwtype,
                'proto_type': arp.ptype
            }

            logger.debug(
                f"ARP: {result['src_ip']} -> "
                f"{result['dst_ip']} ({result['operation_name']})"
            )
            return result

        except Exception as e:
            logger.error(f"ARP parse error: {e}")
            return None
