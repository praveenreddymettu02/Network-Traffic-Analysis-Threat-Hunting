import sys
import os
import time
import json
import platform
import sqlite3
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, jsonify, request, Response
from database.db_manager import DatabaseManager
from capture.capture_manager import CaptureManager
from parser.protocol_analyzer import ProtocolAnalyzer
from parser.dns_parser import DNSParser
from utils.logger import setup_logger
from config import Config
from routes.alert_engine import AlertEngine
from engine.mitre_mapping import get_all_mitre_mappings, get_mitre_mapping

api_bp = Blueprint('api', __name__, url_prefix='/api')
logger = setup_logger('api')

# Try to import psutil, fallback to dummy values if not installed
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed. CPU/Memory will show 0%.")

db = DatabaseManager()
capture_mgr = CaptureManager(db_manager=db)
analyzer = ProtocolAnalyzer()
dns_parser = DNSParser()

# ============================================
# 🔥 ALERT ENGINE INITIALIZATION
# ============================================
alert_engine = AlertEngine(db)

# Start alert engine with Flask app
def start_alert_engine():
    alert_engine.start()
    logger.info("Alert engine started successfully")

# Register callback for real-time alerts
def alert_callback(alert):
    """Callback for new alerts - can be used for WebSocket or SSE"""
    try:
        # Log the alert
        logger.info(f"New Alert: {alert.get('alert_type')} - {alert.get('title')}")
    except Exception as e:
        logger.error(f"Alert callback error: {e}")

alert_engine.register_callback(alert_callback)


# ============================================
# 🔥 HELPER FUNCTIONS
# ============================================
def format_bytes(bytes_per_second):
    """Format bytes per second to human readable format"""
    if bytes_per_second < 1024:
        return f"{bytes_per_second:.2f} B/s"
    elif bytes_per_second < 1024 * 1024:
        return f"{bytes_per_second / 1024:.2f} KB/s"
    elif bytes_per_second < 1024 * 1024 * 1024:
        return f"{bytes_per_second / (1024 * 1024):.2f} MB/s"
    else:
        return f"{bytes_per_second / (1024 * 1024 * 1024):.2f} GB/s"


def format_duration(seconds):
    """Format duration in seconds to human readable format"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds}s"
    elif seconds < 86400:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{hours}h {remaining_minutes}m"
    else:
        days = seconds // 86400
        remaining_hours = (seconds % 86400) // 3600
        return f"{days}d {remaining_hours}h"


# ============================================
# 🔥 PACKETS API
# ============================================
@api_bp.route('/packets', methods=['GET'])
def get_packets():
    limit = request.args.get('limit', 50, type=int)
    session_id = request.args.get('session_id', type=int)
    
    if session_id:
        packets = db.get_session_packets(session_id, limit)
    else:
        packets = db.get_recent_packets(limit)
    
    for pkt in packets:
        if pkt.get('timestamp'):
            pkt['time_local'] = datetime.fromtimestamp(pkt['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(pkt.get('raw_data'), bytes):
            pkt['raw_data'] = pkt['raw_data'].hex()[:100]
    return jsonify(packets)


# ============================================
# 🔥 STATS API
# ============================================
@api_bp.route('/stats', methods=['GET'])
def get_stats():
    session_id = request.args.get('session_id', type=int)
    
    if session_id:
        total = db.get_session_stats(session_id)
        proto_counts = db.get_protocol_counts_for_session(session_id)
        top_src = db.get_top_ips_for_session(session_id, 'src_ip', 5)
        top_dst = db.get_top_ips_for_session(session_id, 'dst_ip', 5)
    else:
        total = db.get_packet_count()
        proto_counts = db.get_protocol_counts()
        top_src = db.get_top_ips('src_ip', 5)
        top_dst = db.get_top_ips('dst_ip', 5)
    
    dns_count = 0
    http_count = 0
    tcp_count = 0
    udp_count = 0
    arp_count = 0
    https_count = 0
    icmp_count = 0
    
    for pc in proto_counts:
        protocol = pc.get('protocol', '')
        count = pc.get('count', 0)
        if protocol == 'DNS':
            dns_count = count
        elif protocol == 'HTTP':
            http_count = count
        elif protocol in ('TLS', 'HTTPS'):
            https_count = count
        elif protocol == 'TCP':
            tcp_count = count
        elif protocol == 'UDP':
            udp_count = count
        elif protocol == 'ARP':
            arp_count = count
        elif protocol == 'ICMP':
            icmp_count = count
    
    return jsonify({
        'total_packets': total if isinstance(total, int) else total.get('total_packets', 0),
        'protocol_counts': proto_counts,
        'top_src_ips': top_src,
        'top_dst_ips': top_dst,
        'dns_count': dns_count,
        'http_count': http_count,
        'tcp_count': tcp_count,
        'udp_count': udp_count,
        'arp_count': arp_count,
        'https_count': https_count,
        'icmp_count': icmp_count,
        'session_id': session_id or db.get_current_session_id()
    })


# ============================================
# 🔥 LIVE STATS with psutil
# ============================================
@api_bp.route('/live-stats', methods=['GET'])
def live_stats():
    session_id = db.get_current_session_id()
    
    # Get CPU and Memory
    if PSUTIL_AVAILABLE:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        memory_usage = psutil.virtual_memory().percent
    else:
        cpu_usage = 0
        memory_usage = 0
    
    total_db_packets = db.get_packet_count()
    if not session_id and total_db_packets == 0:
        return jsonify({
            'status': 'no_session',
            'message': 'No active session or packets. Click Start or Generate Demo Data.',
            'is_running': False,
            'cpu_usage': round(cpu_usage, 1),
            'memory_usage': round(memory_usage, 1),
            'total_packets': 0,
            'packets_per_second': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'arp_packets': 0,
            'dns_queries': 0,
            'http_requests': 0,
            'https_connections': 0,
            'bandwidth': 0,
            'top_source_ips': [],
            'top_destination_ips': []
        }), 200
    
    session_stats = db.get_session_stats(session_id) if session_id else None
    if not session_stats or session_stats.get('total_packets', 0) == 0:
        if total_db_packets > 0:
            conn = db._get_connection()
            b_res = conn.execute("SELECT SUM(length) FROM packets").fetchone()
            total_bytes = b_res[0] if b_res and b_res[0] else 0
            session_stats = {
                'total_packets': total_db_packets,
                'total_bytes': total_bytes
            }

    proto_counts = db.get_protocol_counts()
    top_src = db.get_top_ips('src_ip', 5)
    top_dst = db.get_top_ips('dst_ip', 5)
    recent_packets = db.get_recent_packets(10)
    for pkt in recent_packets:
        if pkt.get('timestamp'):
            pkt['time_local'] = datetime.fromtimestamp(pkt['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(pkt.get('raw_data'), bytes):
            pkt['raw_data'] = pkt['raw_data'].hex()[:100]
    
    # Extract protocol counts
    dns_val = 0
    http_val = 0
    https_val = 0
    tcp_val = 0
    udp_val = 0
    icmp_val = 0
    arp_val = 0
    
    for pc in proto_counts:
        protocol = pc.get('protocol', '')
        count = pc.get('count', 0)
        if protocol == 'DNS':
            dns_val = count
        elif protocol == 'HTTP':
            http_val += count
        elif protocol in ('TLS', 'HTTPS'):
            http_val += count
            https_val = count
        elif protocol == 'TCP':
            tcp_val = count
        elif protocol == 'UDP':
            udp_val = count
        elif protocol == 'ICMP':
            icmp_val = count
        elif protocol == 'ARP':
            arp_val = count
    
    pps = 0
    bandwidth_val = 0
    if session_stats and session_stats.get('total_packets', 0) > 0:
        try:
            conn = db._get_connection()
            cur = conn.execute("SELECT start_time FROM sessions WHERE id = ?", (session_id,))
            result = cur.fetchone()
            if result:
                elapsed = int(time.time()) - result[0]
                if elapsed > 0:
                    pps = session_stats['total_packets'] / elapsed
                    bandwidth_val = session_stats.get('total_bytes', 0) / elapsed
        except:
            pass
            
    # Calculate TCP, UDP totals for diagnostic API
    tcp_packets_total = tcp_val + http_val + https_val
    udp_packets_total = udp_val + dns_val
    
    return jsonify({
        'session_id': session_id,
        'is_running': capture_mgr.running,
        'total_packets': session_stats.get('total_packets', 0) if session_stats else 0,
        'total_bytes': session_stats.get('total_bytes', 0) if session_stats else 0,
        'packets_per_second': round(pps, 2),
        'protocol_counts': proto_counts,
        
        # Existing UI keys
        'dns_count': dns_val,
        'http_count': http_val,
        'https_count': https_val,
        'tcp_count': tcp_val,
        'udp_count': udp_val,
        'icmp_count': icmp_val,
        'arp_count': arp_val,
        'top_src_ips': top_src,
        'top_dst_ips': top_dst,
        'recent_packets': recent_packets,
        
        # Core diagnostic keys requested by user
        'tcp_packets': tcp_packets_total,
        'udp_packets': udp_packets_total,
        'icmp_packets': icmp_val,
        'arp_packets': arp_val,
        'dns_queries': dns_val,
        'http_requests': http_val,
        'https_connections': https_val,
        'bandwidth': round(bandwidth_val, 2),
        'top_source_ips': [{'ip': item['src_ip'], 'count': item['count']} for item in top_src if 'src_ip' in item],
        'top_destination_ips': [{'ip': item['dst_ip'], 'count': item['count']} for item in top_dst if 'dst_ip' in item],
        
        'cpu_usage': round(cpu_usage, 1),
        'memory_usage': round(memory_usage, 1),
        'timestamp': int(time.time())
    })


# ============================================
# 🔥 RECENT ALERTS (Legacy)
# ============================================
@api_bp.route('/alerts/recent', methods=['GET'])
def recent_alerts():
    limit = request.args.get('limit', 10, type=int)
    try:
        raw_alerts = alert_engine.get_alerts(limit=limit)
        formatted_alerts = []
        for a in raw_alerts:
            severity = (a.get('severity') or 'INFO').upper()
            alert_type = 'danger' if severity in ('CRITICAL', 'HIGH') else 'warning' if severity == 'MEDIUM' else 'info'
            formatted_alerts.append({
                'id': a.get('id'),
                'type': alert_type,
                'severity': severity,
                'message': f"{a.get('title')}: {a.get('description')}",
                'mitre_technique_id': a.get('mitre_technique_id'),
                'mitre_tactic': a.get('mitre_tactic'),
                'detection_type': a.get('detection_type'),
                'time_local': a.get('time_local') or datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'details': a.get('details')
            })
        return jsonify(formatted_alerts)
    except Exception as e:
        logger.error(f"Alerts error: {e}")
        return jsonify([])


# ============================================
# 🔥 DNS APIs
# ============================================
@api_bp.route('/dns/live', methods=['GET'])
def dns_live():
    limit = request.args.get('limit', 50, type=int)
    
    dns_logs = db.get_dns_logs(limit, session_only=True)
    
    result = []
    for log in dns_logs:
        answer_records = log.get('answer_records', [])
        if isinstance(answer_records, str):
            try:
                answer_records = json.loads(answer_records)
            except:
                answer_records = []
        
        result.append({
            'id': log.get('id'),
            'timestamp': log.get('timestamp'),
            'time_local': log.get('time_local'),
            'src_ip': log.get('src_ip'),
            'dst_ip': log.get('dst_ip'),
            'domain': log.get('domain'),
            'query_type': log.get('query_type', 'A'),
            'is_response': log.get('is_response', 0),
            'answer_records': answer_records,
            'ttl': log.get('ttl'),
            'rcode': log.get('rcode', 'No Error')
        })
    
    return jsonify({
        'status': 'success',
        'count': len(result),
        'session_id': db.get_current_session_id(),
        'queries': result
    })


@api_bp.route('/dns/count', methods=['GET'])
def dns_count():
    count = db.get_dns_count(session_only=True)
    return jsonify({
        'status': 'success',
        'count': count,
        'session_id': db.get_current_session_id()
    })


@api_bp.route('/dns/top', methods=['GET'])
def dns_top():
    limit = request.args.get('limit', 10, type=int)
    session_id = db.get_current_session_id()
    
    if not session_id:
        return jsonify({'status': 'no_session', 'domains': []})
    
    query = """
    SELECT domain, COUNT(*) as count
    FROM dns_logs
    WHERE session_id = ? AND is_response = 0
    GROUP BY domain
    ORDER BY count DESC
    LIMIT ?
    """
    
    conn = db._get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.execute(query, (session_id, limit))
    result = [dict(row) for row in cur.fetchall()]
    
    return jsonify({
        'status': 'success',
        'session_id': session_id,
        'domains': result
    })


# ============================================
# 🔥 TCP SESSIONS APIs
# ============================================
@api_bp.route('/tcp/sessions', methods=['GET'])
def get_tcp_sessions():
    """Get TCP sessions for current session"""
    limit = request.args.get('limit', 100, type=int)
    status = request.args.get('status', None)
    
    sessions = db.get_tcp_sessions(limit, status)
    return jsonify(sessions)


@api_bp.route('/tcp/stats', methods=['GET'])
def get_tcp_stats():
    """Get TCP session statistics"""
    stats = db.get_tcp_session_stats()
    return jsonify(stats)


@api_bp.route('/tcp/session/<int:session_id>', methods=['GET'])
def get_tcp_session(session_id):
    """Get specific TCP session details"""
    query = """
    SELECT * FROM tcp_sessions WHERE id = ?
    """
    conn = db._get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.execute(query, (session_id,))
    result = cur.fetchone()
    
    if result:
        return jsonify(dict(result))
    return jsonify({'error': 'Session not found'}), 404


# ============================================
# 🔥 PROTOCOL TIMELINE
# ============================================
@api_bp.route('/protocols/timeline', methods=['GET'])
def protocol_timeline():
    """Get protocol timeline data"""
    interval = request.args.get('interval', 60, type=int)
    session_id = db.get_current_session_id()
    
    if not session_id:
        return jsonify([])
    
    query = """
    SELECT 
        (timestamp / ?) * ? as time_bucket,
        protocol,
        COUNT(*) as count
    FROM packets
    WHERE session_id = ?
    GROUP BY time_bucket, protocol
    ORDER BY time_bucket
    LIMIT 100
    """
    
    conn = db._get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.execute(query, (interval, interval, session_id))
    result = [dict(row) for row in cur.fetchall()]
    
    return jsonify(result)


# ============================================
# 🔥 CAPTURE CONTROL
# ============================================
@api_bp.route('/capture/start', methods=['POST'])
def start_capture():
    try:
        if capture_mgr.running:
            return jsonify({'status': 'error', 'message': 'Capture is already running'}), 400

        data = request.get_json(silent=True) or {}
        count = data.get('count', 0)
        timeout = data.get('timeout', None)
        interface = data.get('interface')

        success, message, session_id = capture_mgr.start_capture(count=count, timeout=timeout, interface=interface)
        if not success:
            logger.warning(f"Capture start rejected: {message}")
            return jsonify({'status': 'error', 'message': message}), 400

        return jsonify({
            'status': 'started',
            'message': message,
            'session_id': session_id
        }), 200
    except Exception as e:
        logger.error(f"Start capture error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/capture/stop', methods=['POST'])
def stop_capture():
    try:
        if not capture_mgr.running:
            return jsonify({'status': 'not running', 'message': 'Capture is not currently active'}), 400

        session_id = capture_mgr.get_session_id()
        success, message, ended_session = capture_mgr.stop_capture()
        return jsonify({
            'status': 'stopped' if success else 'stopping',
            'message': message,
            'session_id': ended_session or session_id
        }), 200
    except Exception as e:
        logger.error(f"Stop capture error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/capture/status', methods=['GET'])
def capture_status():
    session_id = db.get_current_session_id()
    session_stats = db.get_session_stats(session_id) if session_id else None
    can_cap, cap_reason = capture_mgr.can_capture()
    return jsonify({
        'running': capture_mgr.running,
        'packets_captured': capture_mgr.get_packet_count(),
        'session_id': session_id,
        'session_stats': session_stats,
        'last_error': getattr(capture_mgr, 'last_error', None),
        'interface': capture_mgr.interface,
        'can_capture': can_cap,
        'capture_message': cap_reason
    })


@api_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    try:
        interfaces = capture_mgr.get_interfaces()
        return jsonify(interfaces)
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return jsonify([]), 500


# ============================================
# 🔒 SECURE INGESTION API (FOR REMOTE CAPTURE AGENTS / RENDER)
# ============================================
def verify_ingestion_auth():
    """Validate X-API-Key or Bearer token against Config.INGESTION_KEY."""
    expected = getattr(Config, 'INGESTION_KEY', None)
    if not expected:
        return True

    api_key = request.headers.get('X-API-Key')
    if not api_key:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:].strip()

    return api_key == expected


@api_bp.route('/ingest/status', methods=['GET'])
def ingest_status():
    """Status endpoint for remote capture agents to verify server connectivity."""
    if not verify_ingestion_auth():
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized: Invalid or missing API key'
        }), 401

    current_session = db.get_current_session_id()
    total_stored = db.get_packet_count()
    return jsonify({
        'status': 'ready',
        'server_time': int(time.time()),
        'active_session_id': current_session,
        'total_packets': total_stored,
        'total_packets_stored': total_stored,
        'auth_required': bool(getattr(Config, 'INGESTION_KEY', None)),
        'supported_protocols': ['TCP', 'UDP', 'DNS', 'HTTP', 'HTTPS', 'TLS', 'ICMP', 'ARP']
    }), 200


@api_bp.route('/ingest/packets', methods=['POST'])
def ingest_packets():
    """Securely ingest batches of real network packets from remote capture agents."""
    if not verify_ingestion_auth():
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized: Invalid or missing API key. Provide X-API-Key header or Bearer token.'
        }), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid JSON or empty request body'}), 400

    raw_packets = data.get('packets') if isinstance(data, dict) else (data if isinstance(data, list) else None)
    if not raw_packets or not isinstance(raw_packets, list):
        return jsonify({'status': 'error', 'message': 'Request must contain a non-empty list of packets'}), 400

    session_id = None
    if isinstance(data, dict) and data.get('session_id'):
        try:
            session_id = int(data['session_id'])
        except (ValueError, TypeError):
            session_id = None

    if not session_id:
        session_id = db.get_active_session_id() or db.get_current_session_id()
        if not session_id:
            session_id = db.create_session()

    db.current_session_id = session_id
    ingested_count = 0
    current_time = time.time()

    for pkt in raw_packets:
        if not isinstance(pkt, dict):
            continue

        pkt_timestamp = pkt.get('timestamp')
        try:
            pkt_timestamp = int(pkt_timestamp) if pkt_timestamp else int(current_time)
        except (ValueError, TypeError):
            pkt_timestamp = int(current_time)

        src_ip = pkt.get('src_ip')
        dst_ip = pkt.get('dst_ip')
        protocol = str(pkt.get('protocol') or 'IP').upper()
        length = int(pkt.get('length') or 64)

        packet_record = {
            'session_id': session_id,
            'timestamp': pkt_timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_mac': pkt.get('src_mac'),
            'dst_mac': pkt.get('dst_mac'),
            'src_port': pkt.get('src_port'),
            'dst_port': pkt.get('dst_port'),
            'protocol': protocol,
            'length': length,
            'ttl': pkt.get('ttl'),
            'tcp_flags': pkt.get('tcp_flags'),
            'raw_data': pkt.get('raw_data')
        }

        db.insert_packet(packet_record)
        ingested_count += 1

        if protocol == 'TCP' or (pkt.get('src_port') and pkt.get('dst_port')):
            try:
                capture_mgr.tcp_tracker.process_packet(packet_record)
            except Exception:
                pass

        dns_info = pkt.get('dns')
        if dns_info and isinstance(dns_info, dict) and dns_info.get('domain'):
            try:
                db.insert_dns_log(
                    domain=dns_info.get('domain'),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    query_type=dns_info.get('query_type', 'A'),
                    is_response=int(dns_info.get('is_response', 0)),
                    answers=dns_info.get('answers', []),
                    rcode=dns_info.get('rcode')
                )
            except Exception:
                pass

        tls_info = pkt.get('tls')
        if tls_info and isinstance(tls_info, dict) and tls_info.get('sni'):
            try:
                db.insert_dns_log(
                    domain=tls_info.get('sni'),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    query_type='SNI',
                    is_response=0,
                    answers=[],
                    rcode=None
                )
            except Exception:
                pass

    db._flush_packet_queue()
    db_total = db.get_packet_count()

    return jsonify({
        'status': 'success',
        'ingested': ingested_count,
        'session_id': session_id,
        'db_total_packets': db_total,
        'timestamp': int(current_time)
    }), 200


# ============================================
# 🔥 DEMO TRAFFIC GENERATION API
# ============================================
@api_bp.route('/demo/generate', methods=['POST', 'GET'])
def generate_demo():
    """Endpoint to generate realistic SOC demo network traffic and alerts."""
    try:
        from utils.demo_generator import generate_demo_traffic
        count = request.args.get('count', 120, type=int)
        if request.is_json:
            data = request.get_json(silent=True) or {}
            count = data.get('count', count)
        result = generate_demo_traffic(db, alert_engine, count=count)
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error generating demo data: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/demo/status', methods=['GET'])
def demo_status():
    """Check how many packets and alerts are currently in the database."""
    return jsonify({
        'status': 'success',
        'packet_count': db.get_packet_count(),
        'has_data': db.get_packet_count() > 0
    })


@api_bp.route('/recent-packets', methods=['GET'])
def get_recent_packets_api():
    try:
        limit = request.args.get('limit', 50, type=int)
        packets = db.get_recent_packets(limit)
        formatted_packets = []
        for pkt in packets:
            formatted_packets.append({
                'timestamp': pkt.get('timestamp'),
                'time_local': datetime.fromtimestamp(pkt.get('timestamp')).strftime('%Y-%m-%d %H:%M:%S') if pkt.get('timestamp') else None,
                'source_ip': pkt.get('src_ip'),
                'destination_ip': pkt.get('dst_ip'),
                'protocol': pkt.get('protocol'),
                'source_port': pkt.get('src_port'),
                'destination_port': pkt.get('dst_port'),
                'packet_length': pkt.get('length')
            })
        return jsonify(formatted_packets)
    except Exception as e:
        logger.error(f"Error getting recent packets: {e}")
        return jsonify([]), 500


# ============================================
# 🔥 TOP TALKERS
# ============================================
@api_bp.route('/top/talkers', methods=['GET'])
def top_talkers():
    limit = request.args.get('limit', 10, type=int)
    
    try:
        session_id = db.get_current_session_id()
        
        if not session_id:
            return jsonify([])
        
        query = """
        SELECT 
            src_ip as ip,
            COUNT(*) as packets,
            SUM(length) as bytes
        FROM packets
        WHERE session_id = ? 
            AND src_ip IS NOT NULL 
            AND src_ip != ''
            AND src_ip != '0.0.0.0'
            AND src_ip != '::'
            AND src_ip != 'Unknown'
        GROUP BY src_ip
        ORDER BY bytes DESC
        LIMIT ?
        """
        
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, (session_id, limit))
        result = [dict(row) for row in cur.fetchall()]
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Top talkers error: {e}")
        return jsonify([]), 500


# ============================================
# 🔥 SYSTEM INFO
# ============================================
@api_bp.route('/system/info', methods=['GET'])
def system_info():
    info = {
        'os': platform.system() + ' ' + platform.release(),
        'python': sys.version.split()[0],
        'hostname': platform.node(),
        'architecture': platform.machine(),
        'processor': platform.processor() or 'Unknown'
    }
    try:
        from config import Config
        db_path = Config.DATABASE_PATH
        if os.path.exists(db_path):
            info['db_size'] = os.path.getsize(db_path)
        else:
            info['db_size'] = 0
    except Exception:
        info['db_size'] = 0
    return jsonify(info)


# ============================================
# 🔥 SEARCH
# ============================================
@api_bp.route('/packets/search', methods=['GET'])
def search_packets():
    ip = request.args.get('ip', '')
    domain = request.args.get('domain', '')
    search_term = ip or domain
    if not search_term:
        return jsonify({'error': 'Please provide ip or domain parameter'}), 400
    query = """
    SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, 
           protocol, length, tcp_flags,
           datetime(timestamp, 'unixepoch', 'localtime') as time_local
    FROM packets WHERE src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ?
    ORDER BY timestamp DESC LIMIT 100
    """
    search_pattern = f"%{search_term}%"
    try:
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, (search_pattern, search_pattern, search_pattern))
        result = [dict(row) for row in cur.fetchall()]
        return jsonify(result)
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# 🔥 TRAFFIC ENDPOINTS
# ============================================
@api_bp.route('/traffic/timeline', methods=['GET'])
def traffic_timeline():
    interval = request.args.get('interval', 60, type=int)
    return jsonify(db.get_traffic_over_time(interval))


@api_bp.route('/traffic/hourly', methods=['GET'])
def traffic_hourly():
    return jsonify(db.get_traffic_by_hour())


@api_bp.route('/traffic/daily', methods=['GET'])
def traffic_daily():
    return jsonify(db.get_traffic_by_day())


@api_bp.route('/traffic/weekly', methods=['GET'])
def traffic_weekly():
    return jsonify(db.get_traffic_by_week())


@api_bp.route('/traffic/monthly', methods=['GET'])
def traffic_monthly():
    return jsonify(db.get_traffic_by_month())


# ============================================
# 🔥 BANDWIDTH & PPS - ENHANCED VERSION
# ============================================
@api_bp.route('/traffic/bandwidth', methods=['GET'])
def traffic_bandwidth():
    """
    Get bandwidth and PPS data
    Query parameters:
    - interval: Time window in seconds (default: 5)
    - session_id: Specific session ID (optional, uses current if not provided)
    - human: Return human-readable values (true/false, default: false)
    """
    try:
        # Get parameters
        interval = request.args.get('interval', 5, type=int)
        session_id = request.args.get('session_id', type=int)
        human_readable = request.args.get('human', 'false').lower() == 'true'
        
        # Validate interval
        if interval < 1:
            interval = 1
        elif interval > 300:
            interval = 300  # Max 5 minutes
        
        # If no session_id provided, use current session
        if not session_id:
            session_id = db.get_current_session_id()
        
        # If still no session, return empty data
        if not session_id:
            return jsonify({
                'status': 'no_session',
                'message': 'No active session found',
                'packets': 0,
                'bytes': 0,
                'pps': 0,
                'bandwidth': 0,
                'bandwidth_human': '0 B/s',
                'pps_human': '0 pps',
                'interval': interval,
                'session_id': None,
                'timestamp': int(time.time())
            })
        
        # Get packets from specified interval
        query = """
        SELECT 
            COUNT(*) as packet_count,
            SUM(length) as total_bytes,
            AVG(length) as avg_packet_size,
            MAX(length) as max_packet_size,
            MIN(length) as min_packet_size
        FROM packets
        WHERE session_id = ? 
            AND timestamp > strftime('%s', 'now', ?)
        """
        
        # Use parameterized interval
        interval_param = f'-{interval} seconds'
        
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, (session_id, interval_param))
        result = cur.fetchone()
        
        if not result or result['packet_count'] == 0:
            return jsonify({
                'status': 'no_data',
                'message': 'No packets in the specified interval',
                'packets': 0,
                'bytes': 0,
                'pps': 0,
                'bandwidth': 0,
                'bandwidth_human': '0 B/s',
                'pps_human': '0 pps',
                'avg_packet_size': 0,
                'max_packet_size': 0,
                'min_packet_size': 0,
                'interval': interval,
                'session_id': session_id,
                'timestamp': int(time.time())
            })
        
        packet_count = result['packet_count'] or 0
        total_bytes = result['total_bytes'] or 0
        
        # Calculate rates
        pps = packet_count / interval
        bandwidth = total_bytes / interval
        
        # Format human-readable values
        bandwidth_human = format_bytes(bandwidth)
        pps_human = f"{pps:.2f} pps"
        
        response = {
            'status': 'success',
            'packets': packet_count,
            'bytes': total_bytes,
            'pps': round(pps, 2),
            'bandwidth': round(bandwidth, 2),
            'bandwidth_human': bandwidth_human if human_readable else None,
            'pps_human': pps_human if human_readable else None,
            'avg_packet_size': round(result['avg_packet_size'] or 0, 2),
            'max_packet_size': result['max_packet_size'] or 0,
            'min_packet_size': result['min_packet_size'] or 0,
            'interval': interval,
            'session_id': session_id,
            'timestamp': int(time.time())
        }
        
        # Remove None values if not needed
        if not human_readable:
            del response['bandwidth_human']
            del response['pps_human']
        
        return jsonify(response)
        
    except sqlite3.Error as e:
        logger.error(f"Database error in traffic_bandwidth: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(e)}',
            'packets': 0,
            'pps': 0,
            'bandwidth': 0
        }), 500
    except Exception as e:
        logger.error(f"Error in traffic_bandwidth: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Internal server error: {str(e)}',
            'packets': 0,
            'pps': 0,
            'bandwidth': 0
        }), 500


# ============================================
# 🔥 BANDWIDTH HISTORY
# ============================================
@api_bp.route('/traffic/bandwidth/history', methods=['GET'])
def traffic_bandwidth_history():
    """
    Get bandwidth history over time
    Query parameters:
    - duration: Time range in seconds (default: 300)
    - interval: Sampling interval in seconds (default: 10)
    - session_id: Specific session ID (optional)
    - human: Return human-readable values (true/false, default: false)
    """
    try:
        duration = request.args.get('duration', 300, type=int)
        interval = request.args.get('interval', 10, type=int)
        session_id = request.args.get('session_id', type=int)
        human_readable = request.args.get('human', 'false').lower() == 'true'
        
        # Validate parameters
        if duration < 10:
            duration = 10
        if duration > 3600:
            duration = 3600  # Max 1 hour
        if interval < 1:
            interval = 1
        
        if not session_id:
            session_id = db.get_current_session_id()
        
        if not session_id:
            return jsonify({
                'status': 'no_session',
                'message': 'No active session',
                'history': []
            })
        
        # Create time buckets
        query = """
        WITH time_buckets AS (
            SELECT 
                (timestamp / ?) * ? as bucket,
                COUNT(*) as packet_count,
                SUM(length) as total_bytes
            FROM packets
            WHERE session_id = ? 
                AND timestamp > strftime('%s', 'now', ?)
            GROUP BY bucket
            ORDER BY bucket
        )
        SELECT 
            bucket as timestamp,
            packet_count,
            total_bytes,
            CAST(packet_count AS FLOAT) / ? as pps,
            CAST(total_bytes AS FLOAT) / ? as bandwidth
        FROM time_buckets
        """
        
        duration_param = f'-{duration} seconds'
        
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, (interval, interval, session_id, duration_param, interval, interval))
        results = [dict(row) for row in cur.fetchall()]
        
        # Process results
        history = []
        for row in results:
            entry = {
                'timestamp': row['timestamp'],
                'time_local': datetime.fromtimestamp(row['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                'packets': row['packet_count'],
                'bytes': row['total_bytes'],
                'pps': round(row['pps'], 2),
                'bandwidth': round(row['bandwidth'], 2)
            }
            
            if human_readable:
                entry['bandwidth_human'] = format_bytes(row['bandwidth'])
                entry['pps_human'] = f"{row['pps']:.2f} pps"
            
            history.append(entry)
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'duration': duration,
            'interval': interval,
            'history': history,
            'total_points': len(history)
        })
        
    except Exception as e:
        logger.error(f"Error in traffic_bandwidth_history: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'history': []
        }), 500


# ============================================
# 🔥 TRAFFIC SUMMARY
# ============================================
@api_bp.route('/traffic/summary', methods=['GET'])
def traffic_summary():
    """
    Get traffic summary for current session
    Returns: Total packets, bytes, average PPS, peak PPS, etc.
    """
    try:
        session_id = db.get_current_session_id()
        
        if not session_id:
            return jsonify({
                'status': 'no_session',
                'message': 'No active session',
                'total_packets': 0,
                'total_bytes': 0,
                'avg_pps': 0,
                'avg_bandwidth': 0,
                'peak_pps': 0,
                'peak_bandwidth': 0,
                'session_duration': 0,
                'unique_src_ips': 0,
                'unique_dst_ips': 0
            })
        
        # Get session stats
        session_stats = db.get_session_stats(session_id)
        
        # Get session duration
        conn = db._get_connection()
        cur = conn.execute("SELECT start_time FROM sessions WHERE id = ?", (session_id,))
        result = cur.fetchone()
        
        session_duration = 0
        if result:
            session_duration = int(time.time()) - result[0]
        
        # Get peak PPS and bandwidth (max in any 5-second window)
        query_peak = """
        SELECT 
            MAX(packet_count) as peak_packets,
            MAX(total_bytes) as peak_bytes,
            AVG(packet_count) as avg_packets,
            AVG(total_bytes) as avg_bytes
        FROM (
            SELECT 
                COUNT(*) as packet_count,
                SUM(length) as total_bytes
            FROM packets
            WHERE session_id = ?
            GROUP BY timestamp / 5
        )
        """
        
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query_peak, (session_id,))
        peak_result = cur.fetchone()
        
        # Get unique IPs
        query_ips = """
        SELECT 
            COUNT(DISTINCT src_ip) as unique_src,
            COUNT(DISTINCT dst_ip) as unique_dst
        FROM packets
        WHERE session_id = ?
            AND src_ip IS NOT NULL
            AND dst_ip IS NOT NULL
            AND src_ip != ''
            AND dst_ip != ''
            AND src_ip != '0.0.0.0'
            AND dst_ip != '0.0.0.0'
        """
        
        conn = db._get_connection()
        cur = conn.execute(query_ips, (session_id,))
        ip_result = cur.fetchone()
        
        total_packets = session_stats.get('total_packets', 0) if session_stats else 0
        total_bytes = session_stats.get('total_bytes', 0) if session_stats else 0
        
        avg_pps = total_packets / session_duration if session_duration > 0 else 0
        avg_bandwidth = total_bytes / session_duration if session_duration > 0 else 0
        
        peak_pps = peak_result['peak_packets'] / 5 if peak_result and peak_result['peak_packets'] else 0
        peak_bandwidth = peak_result['peak_bytes'] / 5 if peak_result and peak_result['peak_bytes'] else 0
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'total_bytes_human': format_bytes(total_bytes) if total_bytes > 0 else '0 B',
            'avg_pps': round(avg_pps, 2),
            'avg_bandwidth': round(avg_bandwidth, 2),
            'avg_bandwidth_human': format_bytes(avg_bandwidth) if avg_bandwidth > 0 else '0 B/s',
            'peak_pps': round(peak_pps, 2),
            'peak_bandwidth': round(peak_bandwidth, 2),
            'peak_bandwidth_human': format_bytes(peak_bandwidth) if peak_bandwidth > 0 else '0 B/s',
            'session_duration': session_duration,
            'session_duration_human': format_duration(session_duration),
            'unique_src_ips': ip_result[0] if ip_result else 0,
            'unique_dst_ips': ip_result[1] if ip_result else 0
        })
        
    except Exception as e:
        logger.error(f"Error in traffic_summary: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# ============================================
# 🔥 TRAFFIC ALERTS
# ============================================
@api_bp.route('/traffic/alerts', methods=['GET'])
def traffic_alerts():
    """
    Check if current traffic exceeds thresholds
    Returns: Alert status for bandwidth and PPS
    """
    try:
        session_id = db.get_current_session_id()
        
        if not session_id:
            return jsonify({
                'status': 'no_session',
                'alerts': []
            })
        
        # Get current traffic (last 5 seconds)
        query = """
        SELECT 
            COUNT(*) as packet_count,
            SUM(length) as total_bytes
        FROM packets
        WHERE session_id = ? 
            AND timestamp > strftime('%s', 'now', '-5 seconds')
        """
        
        conn = db._get_connection()
        cur = conn.execute(query, (session_id,))
        result = cur.fetchone()
        
        packet_count = result[0] or 0
        total_bytes = result[1] or 0
        
        pps = packet_count / 5
        bandwidth = total_bytes / 5
        
        # Define thresholds (configurable)
        threshold_pps = 1000  # 1000 packets per second
        threshold_bandwidth = 10 * 1024 * 1024  # 10 MB/s
        
        alerts = []
        
        if pps > threshold_pps:
            alerts.append({
                'type': 'warning',
                'message': f'High PPS: {pps:.2f} pps (threshold: {threshold_pps})',
                'value': round(pps, 2),
                'threshold': threshold_pps
            })
        
        if bandwidth > threshold_bandwidth:
            alerts.append({
                'type': 'warning',
                'message': f'High bandwidth: {format_bytes(bandwidth)} (threshold: {format_bytes(threshold_bandwidth)})',
                'value': round(bandwidth, 2),
                'threshold': threshold_bandwidth,
                'value_human': format_bytes(bandwidth),
                'threshold_human': format_bytes(threshold_bandwidth)
            })
        
        if not alerts:
            alerts.append({
                'type': 'info',
                'message': 'Normal traffic levels',
                'pps': round(pps, 2),
                'bandwidth': round(bandwidth, 2),
                'bandwidth_human': format_bytes(bandwidth)
            })
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'alerts': alerts,
            'current_pps': round(pps, 2),
            'current_bandwidth': round(bandwidth, 2),
            'current_bandwidth_human': format_bytes(bandwidth),
            'timestamp': int(time.time())
        })
        
    except Exception as e:
        logger.error(f"Error in traffic_alerts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'alerts': []
        }), 500


# ============================================
# 🔥 TRAFFIC BY PROTOCOL
# ============================================
@api_bp.route('/traffic/protocols', methods=['GET'])
def traffic_by_protocol():
    """
    Get traffic breakdown by protocol
    Returns: Bandwidth and packet count per protocol
    """
    try:
        session_id = db.get_current_session_id()
        
        if not session_id:
            return jsonify({
                'status': 'no_session',
                'protocols': []
            })
        
        # Get traffic by protocol (last 60 seconds)
        query = """
        SELECT 
            protocol,
            COUNT(*) as packet_count,
            SUM(length) as total_bytes,
            AVG(length) as avg_size
        FROM packets
        WHERE session_id = ? 
            AND timestamp > strftime('%s', 'now', '-60 seconds')
            AND protocol IS NOT NULL
            AND protocol != ''
        GROUP BY protocol
        ORDER BY total_bytes DESC
        """
        
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query, (session_id,))
        results = [dict(row) for row in cur.fetchall()]
        
        # Calculate percentages
        total_bytes = sum(row['total_bytes'] for row in results)
        
        for row in results:
            row['percentage'] = (row['total_bytes'] / total_bytes * 100) if total_bytes > 0 else 0
            row['bandwidth'] = row['total_bytes'] / 60  # bytes per second
            row['bandwidth_human'] = format_bytes(row['bandwidth'])
            row['pps'] = row['packet_count'] / 60
        
        return jsonify({
            'status': 'success',
            'session_id': session_id,
            'time_window': 60,
            'total_bytes': total_bytes,
            'total_bytes_human': format_bytes(total_bytes) if total_bytes > 0 else '0 B',
            'protocols': results
        })
        
    except Exception as e:
        logger.error(f"Error in traffic_by_protocol: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'protocols': []
        }), 500


# ============================================
# 🔥 PROTOCOL DNS (Existing)
# ============================================
@api_bp.route('/protocols/dns', methods=['GET'])
def dns_stats():
    dns_packets = db.get_dns_queries()
    return jsonify({'dns_count': len(dns_packets)})


@api_bp.route('/protocols/dns/top', methods=['GET'])
def top_dns_domains():
    dns_packets = db.get_dns_queries()
    domains = {}
    for pkt in dns_packets:
        try:
            domain = pkt.get('dst_ip', 'unknown')
            domains[domain] = domains.get(domain, 0) + 1
        except Exception:
            continue
    sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({'top_domains': sorted_domains})


# ============================================
# 🔥 ALERT ENGINE API
# ============================================

@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """
    Get alerts with filtering
    Query parameters:
    - limit: Number of alerts (default: 100)
    - severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    - resolved: Filter by resolved status (true/false)
    - type: Filter by alert type
    - mitre_technique_id: Filter by MITRE technique ID (e.g. T1110)
    - mitre_tactic: Filter by MITRE tactic (e.g. Credential Access)
    - source_ip: Filter by source IP
    - detection_type: Filter by detection type
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        severity = request.args.get('severity')
        resolved = request.args.get('resolved')
        alert_type = request.args.get('type')
        mitre_technique_id = request.args.get('mitre_technique_id')
        mitre_tactic = request.args.get('mitre_tactic')
        source_ip = request.args.get('source_ip')
        detection_type = request.args.get('detection_type')
        
        # Parse resolved parameter
        resolved_bool = None
        if resolved is not None:
            resolved_bool = resolved.lower() == 'true'
        
        alerts = alert_engine.get_alerts(
            limit=limit,
            severity=severity,
            resolved=resolved_bool,
            alert_type=alert_type,
            mitre_technique_id=mitre_technique_id,
            mitre_tactic=mitre_tactic,
            source_ip=source_ip,
            detection_type=detection_type
        )
        
        return jsonify({
            'status': 'success',
            'count': len(alerts),
            'alerts': alerts
        })
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get alert statistics"""
    try:
        stats = alert_engine.get_alert_stats()
        return jsonify({
            'status': 'success',
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting alert stats: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Resolve a specific alert"""
    try:
        success = alert_engine.resolve_alert(alert_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Alert resolved successfully'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Alert not found or already resolved'
            }), 404
            
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/alerts/resolve/all', methods=['POST'])
def resolve_all_alerts():
    """Resolve all active alerts"""
    try:
        count = alert_engine.resolve_all_alerts()
        
        return jsonify({
            'status': 'success',
            'message': f'Resolved {count} alerts',
            'resolved_count': count
        })
        
    except Exception as e:
        logger.error(f"Error resolving all alerts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/alerts/types', methods=['GET'])
def get_alert_types():
    """Get all available alert types with MITRE mapping information"""
    try:
        mappings = get_all_mitre_mappings()
        alert_types = []
        for alert_type, info in mappings.items():
            alert_types.append({
                'type': alert_type,
                'detection_type': alert_type.lower(),
                'description': info['description'],
                'mitre_technique_id': info['technique_id'],
                'mitre_technique_name': info['technique_name'],
                'mitre_tactic': info['tactic'],
                'mapping_status': info['mapping_status']
            })
        
        return jsonify({
            'status': 'success',
            'types': alert_types
        })
        
    except Exception as e:
        logger.error(f"Error getting alert types: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


# 🔥 MITRE ATT&CK & THREAT HUNTING API
# ============================================

@api_bp.route('/mitre/stats', methods=['GET'])
def get_mitre_stats():
    """
    Get real MITRE ATT&CK statistics from database alerts
    Returns technique count, tactic breakdown, last seen, and status
    """
    try:
        stats = alert_engine.get_mitre_stats()
        return jsonify({
            'status': 'success',
            'count': len(stats),
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Error in mitre_stats: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/mitre/mappings', methods=['GET'])
def get_mitre_mappings_api():
    """Get centralized MITRE ATT&CK technique mapping definitions"""
    try:
        return jsonify({
            'status': 'success',
            'mappings': get_all_mitre_mappings()
        })
    except Exception as e:
        logger.error(f"Error in mitre_mappings: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/hunting/search', methods=['GET'])
def threat_hunting_search():
    """
    Threat hunting endpoint querying real database alerts & network traffic.
    Query parameters:
    - mitre_technique_id: Filter by technique ID (e.g. T1110)
    - mitre_tactic: Filter by tactic (e.g. Credential Access)
    - detection_type: Filter by detection type (e.g. brute_force)
    - severity: Filter by severity
    - source_ip: Filter by source IP
    """
    try:
        mitre_technique_id = request.args.get('mitre_technique_id')
        mitre_tactic = request.args.get('mitre_tactic')
        detection_type = request.args.get('detection_type')
        severity = request.args.get('severity')
        source_ip = request.args.get('source_ip')
        limit = request.args.get('limit', 100, type=int)

        alerts = alert_engine.get_alerts(
            limit=limit,
            severity=severity,
            mitre_technique_id=mitre_technique_id,
            mitre_tactic=mitre_tactic,
            source_ip=source_ip,
            detection_type=detection_type
        )

        return jsonify({
            'status': 'success',
            'count': len(alerts),
            'alerts': alerts
        })
    except Exception as e:
        logger.error(f"Error in threat_hunting_search: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@api_bp.route('/alerts/thresholds', methods=['GET'])
def get_thresholds():
    """Get current alert thresholds"""
    try:
        return jsonify({
            'status': 'success',
            'thresholds': alert_engine.thresholds
        })
        
    except Exception as e:
        logger.error(f"Error getting thresholds: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/alerts/thresholds', methods=['POST'])
def update_thresholds():
    """Update alert thresholds"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400
        
        alert_type = data.get('alert_type')
        if not alert_type:
            return jsonify({
                'status': 'error',
                'message': 'alert_type is required'
            }), 400
        
        # Remove alert_type from kwargs
        kwargs = {k: v for k, v in data.items() if k != 'alert_type'}
        
        success = alert_engine.update_threshold(alert_type, **kwargs)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Thresholds updated for {alert_type}',
                'thresholds': alert_engine.thresholds[alert_type]
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Invalid alert type: {alert_type}'
            }), 400
            
    except Exception as e:
        logger.error(f"Error updating thresholds: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@api_bp.route('/alerts/realtime', methods=['GET'])
def realtime_alerts():
    """
    Server-Sent Events endpoint for real-time alerts
    Use EventSource in JavaScript to connect
    """
    def generate():
        last_alert_id = 0
        while True:
            try:
                # Get new alerts
                alerts = alert_engine.get_alerts(limit=10)
                new_alerts = [a for a in alerts if a.get('id', 0) > last_alert_id]
                
                if new_alerts:
                    last_alert_id = max(a.get('id', 0) for a in new_alerts)
                    yield f"data: {json.dumps(new_alerts)}\n\n"
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"SSE error: {e}")
                time.sleep(5)
    
    return Response(generate(), mimetype='text/event-stream')


# ============================================
# 🔥 ALERT ENGINE STATUS
# ============================================
@api_bp.route('/alerts/engine/status', methods=['GET'])
def alert_engine_status():
    """Get alert engine status"""
    try:
        return jsonify({
            'status': 'success',
            'running': alert_engine.running,
            'alerts_in_memory': len(alert_engine.alerts),
            'thresholds': alert_engine.thresholds,
            'timestamp': int(time.time())
        })
    except Exception as e:
        logger.error(f"Error getting alert engine status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


def generate_hex_dump(data_bytes):
    if not data_bytes:
        return "No payload data available."
    
    if isinstance(data_bytes, str):
        try:
            data_bytes = bytes.fromhex(data_bytes)
        except ValueError:
            data_bytes = data_bytes.encode('utf-8')
            
    lines = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        hex_str = hex_str.ljust(47)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_str}  |{ascii_str}|")
    return "\n".join(lines)


@api_bp.route('/packet/<int:packet_id>', methods=['GET'])
def get_packet_details(packet_id):
    try:
        conn = db._get_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM packets WHERE id = ?", (packet_id,))
        row = cur.fetchone()
        conn.row_factory = None
        
        if not row:
            return jsonify({'status': 'error', 'message': 'Packet not found'}), 404
            
        pkt = dict(row)
        
        if pkt.get('timestamp'):
            pkt['time_local'] = datetime.fromtimestamp(pkt.get('timestamp')).strftime('%Y-%m-%d %H:%M:%S')
            
        raw_data = pkt.get('raw_data')
        hex_dump = "No payload data available."
        scapy_show = "Could not reconstruct packet layers."
        
        if raw_data:
            hex_dump = generate_hex_dump(raw_data)
            
            try:
                from scapy.all import Ether, IP
                if len(raw_data) > 0 and (raw_data[0] & 0xf0) == 0x40:
                    scapy_pkt = IP(raw_data)
                else:
                    scapy_pkt = Ether(raw_data)
                scapy_show = scapy_pkt.show(dump=True)
            except Exception as e:
                scapy_show = f"Scapy parser error: {e}"
                
        if 'raw_data' in pkt:
            del pkt['raw_data']
            
        return jsonify({
            'status': 'success',
            'packet': pkt,
            'hex_dump': hex_dump,
            'layers': scapy_show
        })
    except Exception as e:
        logger.error(f"Error getting packet details: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500