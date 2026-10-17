from scapy.all import Raw, TCP
from utils.logger import setup_logger

logger = setup_logger('tls_parser')

class TLSParser:
    """Parse TLS ClientHello for SNI extraction"""
    
    @staticmethod
    def parse(packet):
        try:
            if not packet.haslayer(TCP):
                return None
            
            tcp = packet[TCP]
            if tcp.dport != 443 and tcp.sport != 443:
                return None
            
            if not packet.haslayer(Raw):
                return None
            
            payload = packet[Raw].load
            
            if len(payload) < 5:
                return None
            
            # Content Type: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application Data
            if payload[0] not in (20, 21, 22, 23):
                return None
            
            # TLS record version
            version_map = {
                (3, 0): "SSL 3.0",
                (3, 1): "TLS 1.0",
                (3, 2): "TLS 1.1",
                (3, 3): "TLS 1.2",
                (3, 4): "TLS 1.3"
            }
            if len(payload) >= 3:
                ver_tuple = (payload[1], payload[2])
                tls_version = version_map.get(ver_tuple, f"{payload[1]}.{payload[2]}")
            else:
                tls_version = "Unknown"
            
            sni = None
            # Check for ClientHello (Handshake = 22, Handshake Type = 1)
            if payload[0] == 22 and len(payload) >= 6 and payload[5] == 1:
                sni = TLSParser._extract_sni(payload)
            
            return {
                'type': 'ClientHello' if sni else 'TLS Record',
                'version': tls_version,
                'sni': sni
            }
        except Exception as e:
            logger.error(f"TLS parse error: {e}")
            return None
    
    @staticmethod
    def _extract_sni(payload):
        """Extract Server Name Indication from TLS ClientHello"""
        try:
            # Skip: Record Header (5) + Handshake Header (4) + Version (2) + Random (32)
            pos = 5 + 4 + 2 + 32
            
            if pos >= len(payload):
                return None
            
            # Session ID
            session_id_len = payload[pos]
            pos += 1 + session_id_len
            
            if pos >= len(payload):
                return None
            
            # Cipher Suites (2 bytes length)
            cipher_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2 + cipher_len
            
            if pos >= len(payload):
                return None
            
            # Compression Methods (1 byte length)
            comp_len = payload[pos]
            pos += 1 + comp_len
            
            if pos >= len(payload):
                return None
            
            # Extensions
            if pos + 2 > len(payload):
                return None
            
            ext_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2
            
            end = pos + ext_len
            
            while pos < end and pos + 4 <= len(payload):
                ext_type = (payload[pos] << 8) | payload[pos + 1]
                ext_data_len = (payload[pos + 2] << 8) | payload[pos + 3]
                pos += 4
                
                # Server Name Indication = 0x0000
                if ext_type == 0x0000:
                    if pos + 2 > len(payload):
                        return None
                    
                    sni_len = (payload[pos] << 8) | payload[pos + 1]
                    pos += 2
                    
                    if pos + sni_len > len(payload):
                        return None
                    
                    # Server Name List
                    while pos < len(payload) and sni_len > 0:
                        name_type = payload[pos]
                        name_len = (payload[pos + 1] << 8) | payload[pos + 2]
                        pos += 3
                        
                        if name_type == 0:  # host_name
                            try:
                                sni = payload[pos:pos + name_len].decode('utf-8')
                                return sni
                            except:
                                return None
                        
                        pos += name_len
                        sni_len -= (3 + name_len)
                
                pos += ext_data_len
            
            return None
        except Exception as e:
            logger.error(f"SNI extraction error: {e}")
            return None