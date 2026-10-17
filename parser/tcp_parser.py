from scapy.all import TCP, IP
from utils.logger import setup_logger

logger = setup_logger('tcp_parser')

class TCPParser:
    """Parse TCP segments"""
    
    @staticmethod
    def parse(packet):
        try:
            if not packet.haslayer(TCP):
                return None
            
            tcp = packet[TCP]
            
            # TCP Flags
            flags = tcp.flags
            flag_names = []
            if flags & 0x01: flag_names.append('FIN')
            if flags & 0x02: flag_names.append('SYN')
            if flags & 0x04: flag_names.append('RST')
            if flags & 0x08: flag_names.append('PSH')
            if flags & 0x10: flag_names.append('ACK')
            if flags & 0x20: flag_names.append('URG')
            if flags & 0x40: flag_names.append('ECE')
            if flags & 0x80: flag_names.append('CWR')
            
            # Options
            options = []
            if tcp.options:
                for opt in tcp.options:
                    if len(opt) >= 2:
                        options.append({
                            'type': opt[0],
                            'value': opt[1] if len(opt) > 1 else None
                        })
            
            result = {
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'seq_num': tcp.seq,
                'ack_num': tcp.ack,
                'flags': ','.join(flag_names) if flag_names else None,
                'window_size': tcp.window,
                'urgent_ptr': tcp.urgptr if hasattr(tcp, 'urgptr') else 0,
                'options': options,
                'payload_length': len(tcp.payload) if tcp.payload else 0,
                'checksum': tcp.chksum
            }
            
            return result
        except Exception as e:
            logger.error(f"TCP parse error: {e}")
            return None
    
    @staticmethod
    def get_connection_key(packet):
        """Get TCP connection identifier"""
        if not packet.haslayer(TCP):
            return None
        
        tcp = packet[TCP]
        ip = packet[IP] if packet.haslayer(IP) else None
        
        if not ip:
            return None
        
        # Sort IPs to make key symmetric
        src_ip = ip.src
        dst_ip = ip.dst
        
        key = f"{src_ip}:{tcp.sport}_{dst_ip}:{tcp.dport}"
        return key
    
    @staticmethod
    def get_handshake_state(flags):
        """Determine TCP handshake state"""
        if flags & 0x02 and not flags & 0x10:
            return 'SYN'
        elif flags & 0x02 and flags & 0x10:
            return 'SYN_ACK'
        elif flags & 0x10 and not flags & 0x02:
            return 'ACK'
        elif flags & 0x01 or flags & 0x04:
            return 'FIN_RST'
        return 'DATA'