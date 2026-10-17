from utils.logger import setup_logger

logger = setup_logger('protocol_detector')


class ProtocolDetector:
    """Detect protocol type from parsed packet"""
    
    @staticmethod
    def detect(parsed_packet):
        """Return protocol name and confidence"""
        try:
            if not parsed_packet:
                return {'protocol': 'Unknown', 'confidence': 0}
            
            protocol = parsed_packet.get('protocol', 'Unknown')
            
            # Check if protocol is already identified
            if protocol in ['ARP', 'DNS', 'HTTP', 'TLS', 'ICMP']:
                return {'protocol': protocol, 'confidence': 100}
            
            # TCP with ports
            if protocol == 'TCP':
                tcp = parsed_packet.get('tcp', {})
                src_port = tcp.get('src_port', 0)
                dst_port = tcp.get('dst_port', 0)
                
                # Well-known ports
                if src_port == 443 or dst_port == 443:
                    return {'protocol': 'HTTPS', 'confidence': 90}
                if src_port == 80 or dst_port == 80:
                    return {'protocol': 'HTTP', 'confidence': 90}
                if src_port == 22 or dst_port == 22:
                    return {'protocol': 'SSH', 'confidence': 80}
                if src_port == 21 or dst_port == 21:
                    return {'protocol': 'FTP', 'confidence': 80}
                if src_port == 25 or dst_port == 25:
                    return {'protocol': 'SMTP', 'confidence': 80}
                if src_port == 143 or dst_port == 143:
                    return {'protocol': 'IMAP', 'confidence': 80}
                if src_port == 110 or dst_port == 110:
                    return {'protocol': 'POP3', 'confidence': 80}
                
                return {'protocol': 'TCP', 'confidence': 70}
            
            # UDP with ports
            if protocol == 'UDP':
                udp = parsed_packet.get('udp', {})
                src_port = udp.get('src_port', 0)
                dst_port = udp.get('dst_port', 0)
                
                if src_port == 53 or dst_port == 53:
                    return {'protocol': 'DNS', 'confidence': 95}
                if src_port in (67, 68) or dst_port in (67, 68):
                    return {'protocol': 'DHCP', 'confidence': 80}
                if src_port == 123 or dst_port == 123:
                    return {'protocol': 'NTP', 'confidence': 80}
                
                return {'protocol': 'UDP', 'confidence': 70}
            
            # ICMP
            if protocol == 'ICMP':
                return {'protocol': 'ICMP', 'confidence': 100}
            
            # ARP
            if protocol == 'ARP':
                return {'protocol': 'ARP', 'confidence': 100}
            
            # IPv6
            ip = parsed_packet.get('ip', {})
            if ip and ip.get('version') == 6:
                return {'protocol': 'IPv6', 'confidence': 80}
            
            return {'protocol': protocol or 'Unknown', 'confidence': 50}
        except Exception as e:
            logger.error(f"Protocol detection error: {e}")
            return {'protocol': 'Error', 'confidence': 0}