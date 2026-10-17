from scapy.all import Raw, TCP
from utils.logger import setup_logger

logger = setup_logger('http_parser')

class HTTPParser:
    """Parse HTTP requests and responses"""
    
    @staticmethod
    def parse(packet):
        try:
            if not packet.haslayer(TCP):
                return None
            
            tcp = packet[TCP]
            if tcp.dport != 80 and tcp.sport != 80:
                return None
            
            if not packet.haslayer(Raw):
                return None
            
            payload = packet[Raw].load
            try:
                data = payload.decode('utf-8', errors='ignore')
            except:
                return None
            
            # Check if it's HTTP
            lines = data.split('\r\n')
            if not lines:
                return None
            
            first_line = lines[0]
            
            # HTTP Request
            if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')):
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    result = {
                        'type': 'request',
                        'method': parts[0],
                        'uri': parts[1],
                        'path': parts[1],
                        'version': parts[2],
                        'headers': {},
                        'body': None
                    }
                    
                    # Parse headers
                    for line in lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            result['headers'][key] = value
                        elif line == '':
                            break
                    
                    # Extract Host
                    if 'Host' in result['headers']:
                        result['host'] = result['headers']['Host']
                    
                    # Extract User-Agent
                    if 'User-Agent' in result['headers']:
                        result['user_agent'] = result['headers']['User-Agent']
                    
                    return result
            
            # HTTP Response
            elif first_line.startswith('HTTP/'):
                parts = first_line.split(' ')
                if len(parts) >= 3:
                    result = {
                        'type': 'response',
                        'version': parts[0],
                        'status_code': parts[1],
                        'status_text': ' '.join(parts[2:]),
                        'headers': {},
                        'body': None
                    }
                    
                    # Parse headers
                    for line in lines[1:]:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            result['headers'][key] = value
                        elif line == '':
                            break
                    
                    return result
            
            return None
        except Exception as e:
            logger.error(f"HTTP parse error: {e}")
            return None