from collections import defaultdict
from utils.logger import setup_logger

logger = setup_logger('tls_analyzer')

class TLSAnalyzer:
    """Analyze TLS traffic"""
    
    def __init__(self):
        self.tls_records = []
        self.sni_counts = defaultdict(int)
    
    def process_packet(self, packet):
        """Process TLS packet"""
        try:
            if not packet:
                return None
            
            tls_info = packet.get('tls')
            ip_info = packet.get('ip')
            
            if not tls_info:
                return None
            
            sni = tls_info.get('sni')
            if not sni:
                return None
            
            timestamp = packet.get('timestamp', 0)
            src_ip = ip_info.get('src_ip') if ip_info else None
            dst_ip = ip_info.get('dst_ip') if ip_info else None
            
            record = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'sni': sni,
                'version': tls_info.get('version')
            }
            
            self.sni_counts[sni] += 1
            self.tls_records.append(record)
            
            return record
        except Exception as e:
            logger.error(f"TLS analysis error: {e}")
            return None
    
    def get_recent_sni(self, limit=50):
        """Get recent SNI records"""
        return self.tls_records[-limit:]
    
    def get_top_sni(self, limit=10):
        """Get top SNI domains"""
        sorted_sni = sorted(self.sni_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_sni[:limit]
    
    def get_sni_count(self):
        """Get total SNI count"""
        return len(self.tls_records)