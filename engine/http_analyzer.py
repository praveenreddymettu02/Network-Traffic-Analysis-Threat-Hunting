from collections import defaultdict
from utils.logger import setup_logger

logger = setup_logger('http_analyzer')


class HTTPAnalyzer:
    """Analyze HTTP traffic"""
    
    def __init__(self):
        self.http_records = []
        self.host_counts = defaultdict(int)
        self.method_counts = defaultdict(int)
    
    def process_packet(self, packet):
        """Process HTTP packet"""
        try:
            if not packet:
                return None
            
            http_info = packet.get('http')
            ip_info = packet.get('ip')
            
            if not http_info:
                return None
            
            timestamp = packet.get('timestamp', 0)
            src_ip = ip_info.get('src_ip') if ip_info else None
            dst_ip = ip_info.get('dst_ip') if ip_info else None
            
            record = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'type': http_info.get('type'),
                'method': http_info.get('method'),
                'uri': http_info.get('uri'),
                'host': http_info.get('host'),
                'user_agent': http_info.get('user_agent'),
                'status_code': http_info.get('status_code'),
                'version': http_info.get('version'),
                'headers': http_info.get('headers', {})
            }
            
            # Count host
            if record.get('host'):
                self.host_counts[record['host']] += 1
            
            # Count method
            if record.get('method'):
                self.method_counts[record['method']] += 1
            
            self.http_records.append(record)
            return record
        except Exception as e:
            logger.error(f"HTTP analysis error: {e}")
            return None
    
    def get_recent_requests(self, limit=50):
        """Get recent HTTP requests"""
        return self.http_records[-limit:]
    
    def get_top_hosts(self, limit=10):
        """Get top hosts"""
        sorted_hosts = sorted(
            self.host_counts.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_hosts[:limit]
    
    def get_request_count(self):
        """Get total HTTP request count"""
        return len(self.http_records)