from scapy.all import DNS
from utils.logger import setup_logger

logger = setup_logger('dns_parser')


class DNSParser:
    """Parse DNS packets with full details like Wireshark"""

    DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
        12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
        33: 'SRV', 255: 'ANY'
    }

    DNS_RCODES = {
        0: 'No Error',
        1: 'Format Error',
        2: 'Server Failure',
        3: 'Name Error (NXDOMAIN)',
        4: 'Not Implemented',
        5: 'Refused'
    }

    @staticmethod
    def parse(packet):
        """Complete DNS parsing with all details"""
        try:
            if not packet.haslayer(DNS):
                return None

            dns = packet[DNS]

            result = {
                'id': dns.id,
                'qr': 'Response' if dns.qr else 'Query',
                'opcode': dns.opcode,
                'rcode': dns.rcode,
                'rcode_text': DNSParser.DNS_RCODES.get(
                    dns.rcode, f'Unknown ({dns.rcode})'),
                'qdcount': dns.qdcount,
                'ancount': dns.ancount,
                'nscount': dns.nscount,
                'arcount': dns.arcount,
                'queries': [],
                'answers': [],
                'authorities': [],
                'additionals': []
            }

            # Parse Queries
            if dns.qd:
                for q in dns.qd:
                    try:
                        name = q.qname.decode() if q.qname else None
                        if name and name.endswith('.'):
                            name = name[:-1]
                    except Exception:
                        name = str(q.qname)

                    result['queries'].append({
                        'name': name,
                        'type': DNSParser.DNS_TYPES.get(q.qtype, q.qtype),
                        'class': q.qclass
                    })

            # Parse Answers (CNAME, A, AAAA, etc.)
            if dns.an:
                for ans in dns.an:
                    try:
                        ans_rrname = getattr(ans, 'rrname', None)
                        name = ans_rrname.decode() if isinstance(ans_rrname, bytes) else str(ans_rrname) if ans_rrname else None
                        if name and name.endswith('.'):
                            name = name[:-1]
                        
                        ans_rdata = getattr(ans, 'rdata', None)
                        rdata = (ans_rdata.decode()
                                 if hasattr(ans_rdata, 'decode')
                                 else str(ans_rdata) if ans_rdata is not None else "")
                    except Exception:
                        name = str(getattr(ans, 'rrname', ''))
                        rdata = str(getattr(ans, 'rdata', ''))

                    result['answers'].append({
                        'name': name,
                        'type': DNSParser.DNS_TYPES.get(ans.type, ans.type),
                        'ttl': getattr(ans, 'ttl', None),
                        'rdata': rdata
                    })

            # Parse Authority Records
            if dns.ns:
                for ns in dns.ns:
                    try:
                        ns_rrname = getattr(ns, 'rrname', None)
                        name = ns_rrname.decode() if isinstance(ns_rrname, bytes) else str(ns_rrname) if ns_rrname else None
                        if name and name.endswith('.'):
                            name = name[:-1]
                        
                        ns_rdata = getattr(ns, 'rdata', None)
                        rdata = (ns_rdata.decode()
                                 if hasattr(ns_rdata, 'decode')
                                 else str(ns_rdata) if ns_rdata is not None else "")
                    except Exception:
                        name = str(getattr(ns, 'rrname', ''))
                        rdata = str(getattr(ns, 'rdata', ''))

                    result['authorities'].append({
                        'name': name,
                        'type': DNSParser.DNS_TYPES.get(ns.type, ns.type),
                        'ttl': getattr(ns, 'ttl', None),
                        'rdata': rdata
                    })

            # Parse Additional Records
            if dns.ar:
                for ar in dns.ar:
                    try:
                        ar_rrname = getattr(ar, 'rrname', None)
                        name = ar_rrname.decode() if isinstance(ar_rrname, bytes) else str(ar_rrname) if ar_rrname else None
                        if name and name.endswith('.'):
                            name = name[:-1]
                        
                        ar_rdata = getattr(ar, 'rdata', None)
                        rdata = (ar_rdata.decode()
                                 if hasattr(ar_rdata, 'decode')
                                 else str(ar_rdata) if ar_rdata is not None else "")
                    except Exception:
                        name = str(getattr(ar, 'rrname', ''))
                        rdata = str(getattr(ar, 'rdata', ''))

                    result['additionals'].append({
                        'name': name,
                        'type': DNSParser.DNS_TYPES.get(ar.type, ar.type),
                        'ttl': getattr(ar, 'ttl', None),
                        'rdata': rdata
                    })

            return result
        except Exception as e:
            logger.error(f"DNS parse error: {e}")
            return None

    @staticmethod
    def extract_domain(packet):
        """Extract domain from DNS query"""
        try:
            if not packet.haslayer(DNS):
                return None

            dns = packet[DNS]
            if dns.qd:
                for q in dns.qd:
                    try:
                        domain = q.qname.decode() if q.qname else None
                        if domain and domain.endswith('.'):
                            domain = domain[:-1]
                        return domain
                    except Exception:
                        continue
            return None
        except Exception as e:
            logger.error(f"DNS domain extraction error: {e}")
            return None

    @staticmethod
    def extract_full_answers(packet):
        """Extract complete DNS answers (CNAME, A, AAAA, etc.)"""
        try:
            if not packet.haslayer(DNS):
                return None

            dns = packet[DNS]
            if not dns.an:
                return None

            answers = []
            for ans in dns.an:
                try:
                    name = ans.rrname.decode() if ans.rrname else None
                    if name and name.endswith('.'):
                        name = name[:-1]
                    rdata = (ans.rdata.decode()
                             if hasattr(ans.rdata, 'decode')
                             else str(ans.rdata))

                    answers.append({
                        'name': name,
                        'type': DNSParser.DNS_TYPES.get(ans.type, ans.type),
                        'ttl': getattr(ans, 'ttl', None),
                        'rdata': rdata
                    })
                except Exception:
                    continue

            return answers
        except Exception as e:
            logger.error(f"DNS answers extraction error: {e}")
            return None

    @staticmethod
    def get_rcode_text(rcode):
        """Get RCODE text"""
        return DNSParser.DNS_RCODES.get(rcode, f'Unknown ({rcode})')
