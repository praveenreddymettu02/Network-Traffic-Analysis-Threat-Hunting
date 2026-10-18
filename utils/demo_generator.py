import time
import random
import json
from datetime import datetime
from engine.mitre_mapping import get_mitre_mapping
from utils.logger import setup_logger

logger = setup_logger('demo_generator')


def generate_demo_traffic(db_manager, alert_engine=None, count=120):
    """
    Generate realistic SOC network traffic, TCP sessions, DNS queries, and MITRE alerts.
    Ideal for demos, presentations, testing, and cloud/GitHub environments where
    live raw packet sniffing is not active.
    """
    try:
        session_id = db_manager.create_session()
        logger.info(f"Generating {count} demo packets for session {session_id}...")

        base_time = int(time.time()) - (count * 2)

        # Hosts definition
        internal_hosts = ['192.168.1.105', '192.168.1.110', '192.168.1.115', '10.0.0.45', '10.0.0.88']
        external_servers = [
            ('142.250.190.46', 'google.com', 443, 'TLS'),
            ('140.82.121.4', 'github.com', 443, 'TLS'),
            ('20.112.52.29', 'microsoft.com', 443, 'TLS'),
            ('104.244.42.1', 'api.twitter.com', 443, 'TLS'),
            ('185.220.101.5', 'c2-beacon-command.xyz', 8080, 'HTTP'),
            ('198.51.100.45', 'malicious-scanner.net', 22, 'TCP'),
            ('8.8.8.8', 'dns.google', 53, 'DNS'),
            ('1.1.1.1', 'one.one.one.one', 53, 'DNS')
        ]
        gateway_ip = '192.168.1.1'
        gateway_mac = '00:50:56:c0:00:01'

        dns_queries = [
            ('google.com', '142.250.190.46', 'A'),
            ('github.com', '140.82.121.4', 'A'),
            ('api.github.com', '140.82.121.6', 'A'),
            ('microsoft.com', '20.112.52.29', 'A'),
            ('cloudflare.com', '104.16.132.229', 'A'),
            ('c2-beacon-command.xyz', '185.220.101.5', 'A'),
            ('exfil-node.ru', '194.26.29.112', 'A'),
            ('internal-service.local', '10.0.0.5', 'A')
        ]

        packets_batch = []

        # 1. Generate DNS Logs & Packets
        for i, (domain, ip_ans, qtype) in enumerate(dns_queries):
            ts = base_time + (i * 10)
            src_ip = random.choice(internal_hosts)
            dst_ip = '8.8.8.8'

            # DNS Query packet
            packets_batch.append({
                'session_id': session_id,
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_mac': '00:1a:2b:3c:4d:5e',
                'dst_mac': gateway_mac,
                'src_port': random.randint(49152, 65535),
                'dst_port': 53,
                'protocol': 'DNS',
                'length': random.randint(60, 85),
                'ttl': 64,
                'tcp_flags': None,
                'raw_data': None
            })

            # DNS Response packet
            packets_batch.append({
                'session_id': session_id,
                'timestamp': ts + 1,
                'src_ip': dst_ip,
                'dst_ip': src_ip,
                'src_mac': gateway_mac,
                'dst_mac': '00:1a:2b:3c:4d:5e',
                'src_port': 53,
                'dst_port': packets_batch[-1]['src_port'],
                'protocol': 'DNS',
                'length': random.randint(90, 150),
                'ttl': 56,
                'tcp_flags': None,
                'raw_data': None
            })

            # Insert to dns_logs table
            db_manager.insert_dns_log(
                domain=domain,
                src_ip=src_ip,
                dst_ip=dst_ip,
                query_type=qtype,
                is_response=1,
                answers=[{'name': domain, 'type': qtype, 'ttl': 300, 'rdata': ip_ans}],
                rcode=0
            )

        # 2. Generate TCP Sessions & Web Traffic
        tcp_sessions_created = 0
        for s_idx in range(12):
            client_ip = random.choice(internal_hosts)
            server_ip, server_domain, server_port, proto = random.choice(external_servers)
            client_port = random.randint(50000, 64000)
            start_ts = base_time + (s_idx * 15)

            # SYN
            packets_batch.append({
                'session_id': session_id,
                'timestamp': start_ts,
                'src_ip': client_ip,
                'dst_ip': server_ip,
                'src_mac': '00:1a:2b:3c:4d:5e',
                'dst_mac': gateway_mac,
                'src_port': client_port,
                'dst_port': server_port,
                'protocol': 'TCP',
                'length': 66,
                'ttl': 64,
                'tcp_flags': 'SYN',
                'raw_data': None
            })

            # SYN-ACK
            packets_batch.append({
                'session_id': session_id,
                'timestamp': start_ts + 1,
                'src_ip': server_ip,
                'dst_ip': client_ip,
                'src_mac': gateway_mac,
                'dst_mac': '00:1a:2b:3c:4d:5e',
                'src_port': server_port,
                'dst_port': client_port,
                'protocol': 'TCP',
                'length': 66,
                'ttl': 54,
                'tcp_flags': 'SYN, ACK',
                'raw_data': None
            })

            # Data packets
            data_count = random.randint(3, 8)
            total_bytes = 132
            for d in range(data_count):
                p_len = random.randint(200, 1450)
                total_bytes += p_len
                packets_batch.append({
                    'session_id': session_id,
                    'timestamp': start_ts + 2 + d,
                    'src_ip': client_ip if d % 2 == 0 else server_ip,
                    'dst_ip': server_ip if d % 2 == 0 else client_ip,
                    'src_mac': '00:1a:2b:3c:4d:5e' if d % 2 == 0 else gateway_mac,
                    'dst_mac': gateway_mac if d % 2 == 0 else '00:1a:2b:3c:4d:5e',
                    'src_port': client_port if d % 2 == 0 else server_port,
                    'dst_port': server_port if d % 2 == 0 else client_port,
                    'protocol': proto,
                    'length': p_len,
                    'ttl': 64 if d % 2 == 0 else 54,
                    'tcp_flags': 'PSH, ACK',
                    'raw_data': None
                })

            # Upsert TCP session into DB
            status = 'closed' if s_idx % 3 == 0 else ('established' if s_idx % 2 == 0 else 'active')
            db_manager.upsert_tcp_session({
                'session_id': session_id,
                'src_ip': client_ip,
                'dst_ip': server_ip,
                'src_port': client_port,
                'dst_port': server_port,
                'start_time': start_ts,
                'last_seen': start_ts + 10,
                'packet_count': data_count + 2,
                'bytes': total_bytes,
                'syn_count': 1,
                'ack_count': data_count + 1,
                'fin_count': 1 if status == 'closed' else 0,
                'rst_count': 0,
                'window_size': 64240,
                'duration': 10,
                'status': status
            })
            tcp_sessions_created += 1

        # 3. Add ARP & ICMP Packets
        for _ in range(15):
            ts = base_time + random.randint(0, count)
            src_ip = random.choice(internal_hosts)
            # ARP
            packets_batch.append({
                'session_id': session_id,
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': gateway_ip,
                'src_mac': '00:1a:2b:3c:4d:5e',
                'dst_mac': 'ff:ff:ff:ff:ff:ff',
                'src_port': None,
                'dst_port': None,
                'protocol': 'ARP',
                'length': 42,
                'ttl': None,
                'tcp_flags': None,
                'raw_data': None
            })
            # ICMP Ping
            packets_batch.append({
                'session_id': session_id,
                'timestamp': ts + 1,
                'src_ip': src_ip,
                'dst_ip': '8.8.8.8',
                'src_mac': '00:1a:2b:3c:4d:5e',
                'dst_mac': gateway_mac,
                'src_port': None,
                'dst_port': None,
                'protocol': 'ICMP',
                'length': 84,
                'ttl': 64,
                'tcp_flags': None,
                'raw_data': None
            })

        # Insert all packets to db
        for pkt in packets_batch:
            pkt['session_id'] = session_id
            db_manager._packet_queue.append(pkt)
        db_manager._flush_packet_queue()

        # Update session totals
        db_manager.end_session(session_id)
        # Keep current session pointing to this valid session
        db_manager.current_session_id = session_id

        # 4. Generate Realistic MITRE ATT&CK Security Alerts
        if alert_engine:
            alerts_to_generate = [
                {
                    'alert_type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'title': 'Port Scan detected from 198.51.100.45',
                    'description': 'Rapid TCP SYN scanning across 32 common ports within 4 seconds',
                    'source_ip': '198.51.100.45',
                    'destination_ip': '192.168.1.105',
                    'source_port': 54321,
                    'destination_port': 22,
                    'protocol': 'TCP',
                    'packet_count': 32,
                    'threshold': 20,
                    'details': 'Target ports: 21, 22, 23, 25, 80, 443, 3389, 8080'
                },
                {
                    'alert_type': 'BRUTE_FORCE',
                    'severity': 'CRITICAL',
                    'title': 'SSH Brute Force attack detected',
                    'description': '18 failed authentication attempts on SSH port 22',
                    'source_ip': '203.0.113.88',
                    'destination_ip': '192.168.1.110',
                    'source_port': 44912,
                    'destination_port': 22,
                    'protocol': 'TCP',
                    'packet_count': 18,
                    'threshold': 10,
                    'details': 'Repeated RST/ACK packets after SSH-2.0 banner exchange'
                },
                {
                    'alert_type': 'BEACONING',
                    'severity': 'HIGH',
                    'title': 'Suspected C2 Beaconing activity',
                    'description': 'Regular periodic HTTP requests (interval 5.0s ± 0.2s) to known suspicious external IP',
                    'source_ip': '192.168.1.115',
                    'destination_ip': '185.220.101.5',
                    'source_port': 58210,
                    'destination_port': 8080,
                    'protocol': 'HTTP',
                    'packet_count': 15,
                    'threshold': 8,
                    'details': 'Destination host: c2-beacon-command.xyz, URI /heartbeat/v1'
                },
                {
                    'alert_type': 'EXCESSIVE_TCP',
                    'severity': 'MEDIUM',
                    'title': 'Excessive TCP Connections',
                    'description': 'Abnormal volume of concurrent TCP connections initiated to external host',
                    'source_ip': '192.168.1.105',
                    'destination_ip': '104.244.42.1',
                    'source_port': 51200,
                    'destination_port': 443,
                    'protocol': 'TCP',
                    'packet_count': 45,
                    'threshold': 30,
                    'details': '45 connections opened within 30 seconds'
                },
                {
                    'alert_type': 'DNS_FLOOD',
                    'severity': 'HIGH',
                    'title': 'DNS Query Flood / Tunneling Activity',
                    'description': 'High frequency of DNS queries with high Shannon entropy subdomains',
                    'source_ip': '10.0.0.45',
                    'destination_ip': '8.8.8.8',
                    'source_port': 61234,
                    'destination_port': 53,
                    'protocol': 'DNS',
                    'packet_count': 64,
                    'threshold': 50,
                    'details': 'Subdomains pattern: chunk-*.exfil-node.ru'
                }
            ]

            for a in alerts_to_generate:
                alert_engine._create_alert(**a)

        logger.info(f"Demo traffic generation complete! Packets: {len(packets_batch)}, Session ID: {session_id}")
        return {
            'status': 'success',
            'session_id': session_id,
            'packet_count': len(packets_batch),
            'tcp_sessions': tcp_sessions_created,
            'message': 'Realistic demo network traffic generated successfully'
        }

    except Exception as e:
        logger.error(f"Error generating demo traffic: {e}", exc_info=True)
        return {'status': 'error', 'message': str(e)}


def seed_demo_data_if_empty(db_manager, alert_engine=None):
    """Checks if the database has any packets. If 0, automatically generates sample data."""
    try:
        count = db_manager.get_packet_count()
        if count == 0:
            logger.info("Database is empty on startup. Auto-seeding initial SOC demonstration data...")
            return generate_demo_traffic(db_manager, alert_engine, count=120)
        else:
            logger.info(f"Database contains {count} packets. Skipping auto-seed.")
            return None
    except Exception as e:
        logger.error(f"Failed to check/seed demo data: {e}")
        return None
