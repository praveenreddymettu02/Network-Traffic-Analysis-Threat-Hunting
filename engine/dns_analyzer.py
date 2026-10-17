from collections import defaultdict
from utils.logger import setup_logger

logger = setup_logger('dns_analyzer')


class DNSAnalyzer:
    """Analyze DNS traffic"""
    
    def __init__(self):
        self.dns_records = []
        self.domain_counts = defaultdict(int)
    
    def process_packet(self, packet):
        """Process DNS packet"""
        try:
            if not packet:
                return None
            
            dns_info = packet.get('dns')
            ip_info = packet.get('ip')
            
            if not dns_info:
                return None
            
            # Extract queries
            queries = dns_info.get('queries', [])
            answers = dns_info.get('answers', [])
            
            if not queries:
                return None
            
            timestamp = packet.get('timestamp', 0)
            src_ip = ip_info.get('src_ip') if ip_info else None
            dst_ip = ip_info.get('dst_ip') if ip_info else None
            
            result = []
            for query in queries:
                domain = query.get('name')
                if not domain:
                    continue
                
                # Count domain
                self.domain_counts[domain] += 1
                
                record = {
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'domain': domain,
                    'query_type': query.get('type'),
                    'is_response': dns_info.get('qr') == 'Response',
                    'answers': []
                }
                
                # Add answers
                for ans in answers:
                    ans_name = ans.get('name', '')
                    if ans.get('name') == domain or domain.endswith(ans_name):
                        record['answers'].append(
                            {
                                'type': ans.get('type'),
                                'ttl': ans.get('ttl'),
                                'rdata': ans.get('rdata'),
                            }
                        )
                
                self.dns_records.append(record)
                result.append(record)
            
            return result
        except Exception as e:
            logger.error(f"DNS analysis error: {e}")
            return None
    
    def get_recent_queries(self, limit=50):
        """Get recent DNS queries"""
        return self.dns_records[-limit:]
    
    def get_top_domains(self, limit=10):
        """Get top queried domains"""
        sorted_domains = sorted(
            self.domain_counts.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_domains[:limit]
    
    def get_query_count(self):
        """Get total DNS query count"""
        return len(self.dns_records)