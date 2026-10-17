import time
from collections import defaultdict
from utils.logger import setup_logger

logger = setup_logger('tcp_session_tracker')

class TCPSessionTracker:
    """Track TCP sessions in real time"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.sessions = {}
        self._session_counter = 0
    
    def process_packet(self, packet_data):
        """Process TCP packet and update session"""
        try:
            # Check if it's TCP
            if packet_data.get('protocol') != 'TCP':
                return
            
            # Flattened packet data — fields at top level
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            src_port = packet_data.get('src_port')
            dst_port = packet_data.get('dst_port')
            flags = packet_data.get('tcp_flags', '')
            length = packet_data.get('length', 0)
            timestamp = packet_data.get('timestamp', int(time.time()))
            
            # Also check nested dicts for backward compatibility
            if not src_ip:
                ip_info = packet_data.get('ip', {})
                src_ip = ip_info.get('src_ip')
                dst_ip = ip_info.get('dst_ip')
            if not src_port:
                tcp_info = packet_data.get('tcp', {})
                src_port = tcp_info.get('src_port')
                dst_port = tcp_info.get('dst_port')
                flags = tcp_info.get('flags', '')

            if not all([src_ip, dst_ip, src_port, dst_port]):
                return
            
            # Create session key (symmetric)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                key = f"{src_ip}:{src_port}_{dst_ip}:{dst_port}"
                reverse = False
            else:
                key = f"{dst_ip}:{dst_port}_{src_ip}:{src_port}"
                reverse = True
            
            # Initialize session if new
            if key not in self.sessions:
                self.sessions[key] = {
                    'src_ip': src_ip if not reverse else dst_ip,
                    'dst_ip': dst_ip if not reverse else src_ip,
                    'src_port': src_port if not reverse else dst_port,
                    'dst_port': dst_port if not reverse else src_port,
                    'start_time': timestamp,
                    'last_seen': timestamp,
                    'packet_count': 0,
                    'bytes': 0,
                    'syn_count': 0,
                    'ack_count': 0,
                    'fin_count': 0,
                    'rst_count': 0,
                    'window_size': 0,
                    'status': 'active'
                }
                self._session_counter += 1
            
            session = self.sessions[key]
            
            # Update session
            session['last_seen'] = timestamp
            session['packet_count'] += 1
            session['bytes'] += length
            session['duration'] = session['last_seen'] - session['start_time']
            
            # Track flags & save on state change or periodically
            old_status = session.get('status')
            if flags and 'SYN' in flags:
                session['syn_count'] += 1
                if session['packet_count'] == 1:
                    session['status'] = 'syn_sent'
            if flags and 'ACK' in flags:
                session['ack_count'] += 1
                if session['syn_count'] > 0 and session['ack_count'] > 0:
                    session['status'] = 'established'
            if flags and 'FIN' in flags:
                session['fin_count'] += 1
                if session['fin_count'] >= 2:
                    session['status'] = 'closed'
            if flags and 'RST' in flags:
                session['rst_count'] += 1
                session['status'] = 'reset'
            
            # Save to database if status changed or every 5 packets
            if session['status'] != old_status or session['packet_count'] % 5 == 0:
                self._save_session(key)
            
            return session
            
        except Exception as e:
            logger.error(f"TCP session tracking error: {e}")
            return None
    
    def _save_session(self, key):
        """Save session to database using UPSERT."""
        if key not in self.sessions:
            return
        
        session = self.sessions[key]
        try:
            session['session_id'] = self.db.get_current_session_id()
            self.db.upsert_tcp_session(session)
        except Exception as e:
            logger.error(f"Save session error: {e}")
    
    def get_sessions(self, limit=50):
        """Get all sessions"""
        return self.db.get_tcp_sessions(limit)
    
    def get_active_sessions(self):
        """Get active sessions"""
        return self.db.get_tcp_sessions(limit=100, status='active')
    
    def get_stats(self):
        """Get session statistics"""
        return self.db.get_tcp_session_stats()
    
    def close_inactive_sessions(self, timeout=300):
        """Close inactive sessions and flush all tracked sessions to database."""
        current_time = int(time.time())
        for key, session in list(self.sessions.items()):
            if session['status'] in ('active', 'syn_sent', 'established'):
                if current_time - session['last_seen'] > timeout:
                    session['status'] = 'closed'
                    logger.info(f"Session {key} closed due to inactivity")
            self._save_session(key)