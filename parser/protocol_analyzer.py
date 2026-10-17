from scapy.all import DNS, Raw, DHCP, BOOTP
from utils.logger import setup_logger

logger = setup_logger('protocol_analyzer')


class ProtocolAnalyzer:

    @staticmethod
    def analyze_dns(packet):
        """Extract DNS information from packet"""
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]
        info = {
            'id': dns.id,
            'qr': 'Response' if dns.qr else 'Query',
            'opcode': dns.opcode,
            'rcode': dns.rcode,
            'queries': [],
            'answers': [],
            'authorities': [],
            'additionals': []
        }

        # Extract queries
        if dns.qd:
            for q in dns.qd:
                query = {
                    'name': q.qname.decode() if q.qname else None,
                    'type': q.qtype,
                    'class': q.qclass
                }
                info['queries'].append(query)

        # Extract answers
        if dns.an:
            for ans in dns.an:
                answer = {
                    'name': ans.rrname.decode() if ans.rrname else None,
                    'type': ans.type,
                    'ttl': ans.ttl,
                    'rdata': (
                        ans.rdata.decode()
                        if hasattr(ans.rdata, 'decode')
                        else str(ans.rdata)
                    )
                }
                info['answers'].append(answer)

        return info

    @staticmethod
    def analyze_http(packet):
        """Extract HTTP information from packet"""
        if not packet.haslayer(Raw):
            return None

        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'HTTP' in payload or 'GET' in payload or 'POST' in payload:
                lines = payload.split('\r\n')
                first_line = lines[0] if lines else ''

                info = {
                    'method': None,
                    'path': None,
                    'version': None,
                    'status_code': None,
                    'headers': {},
                    'body': None
                }

                # Parse first line
                if first_line.startswith(
                    ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')
                ):
                    parts = first_line.split(' ')
                    if len(parts) >= 3:
                        info['method'] = parts[0]
                        info['path'] = parts[1]
                        info['version'] = parts[2]
                elif 'HTTP' in first_line:
                    # Response
                    parts = first_line.split(' ')
                    if len(parts) >= 3:
                        info['version'] = parts[0]
                        info['status_code'] = parts[1]

                # Parse headers
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        info['headers'][key] = value

                return info
        except Exception:
            pass
        return None

    @staticmethod
    def analyze_dhcp(packet):
        """Extract DHCP information"""
        if packet.haslayer(DHCP):
            dhcp = packet[DHCP]
            bootp = packet[BOOTP]

            mac = (
                bootp.chaddr.hex()
                if hasattr(bootp.chaddr, 'hex')
                else str(bootp.chaddr)
            )
            info = {
                'type': 'DHCP',
                'client_ip': bootp.ciaddr,
                'server_ip': bootp.siaddr,
                'gateway_ip': bootp.giaddr,
                'mac': mac,
                'options': []
            }

            if dhcp.options:
                for opt in dhcp.options:
                    if isinstance(opt, tuple) and len(opt) >= 2:
                        val = (
                            opt[1].hex()
                            if isinstance(opt[1], bytes)
                            else opt[1]
                        )
                        info['options'].append({
                            'type': opt[0],
                            'value': val
                        })

            return info
        return None

    @staticmethod
    def get_top_domains(packets):
        """Get top DNS domains from packet list"""
        domains = {}
        for packet in packets:
            try:
                if packet.get('protocol') == 'DNS':
                    dns_info = packet.get('dns', {})
                    queries = dns_info.get('queries', [])
                    for q in queries:
                        domain = q.get('name', '')
                        if domain:
                            # Strip trailing dot
                            domain = domain.rstrip('.')
                            domains[domain] = domains.get(domain, 0) + 1
            except Exception:
                continue
        return sorted(
            domains.items(), key=lambda x: x[1], reverse=True
        )[:10]

