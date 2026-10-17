import time
import sqlite3
import threading
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Optional
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from utils.logger import setup_logger
from engine.mitre_mapping import get_mitre_mapping, get_all_mitre_mappings

logger = setup_logger('alert_engine')

# Import configuration
try:
    from routes.alert_config import *
except ImportError:
    # Default configuration if alert_config.py doesn't exist
    ENABLE_EMAIL_ALERTS = False
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USE_TLS = True
    SMTP_USERNAME = ''
    SMTP_PASSWORD = ''
    ALERT_EMAIL_RECIPIENTS = []
    ALERT_EMAIL_SENDER = ''
    ALERT_EMAIL_SUBJECT_PREFIX = '[Network Alert] '
    EMAIL_MIN_SEVERITY = 'MEDIUM'

@dataclass
class Alert:
    """Alert data structure"""
    id: Optional[int] = None
    alert_type: str = ''
    detection_type: str = ''
    severity: str = ''
    title: str = ''
    description: str = ''
    source_ip: str = ''
    destination_ip: str = ''
    source_port: int = None
    destination_port: int = None
    protocol: str = ''
    packet_count: int = 0
    threshold: int = 0
    details: str = ''
    evidence: str = ''
    mitre_technique: str = ''
    mitre_technique_id: str = ''
    mitre_technique_name: str = ''
    mitre_tactic: str = ''
    timestamp: int = 0
    session_id: int = None
    resolved: bool = False
    resolved_at: int = None
    
    def to_dict(self):
        data = asdict(self)
        if self.timestamp:
            data['time_local'] = datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return data


class AlertEngine:
    """Real-time Alert Engine for network security monitoring"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.running = False
        self.alert_thread = None
        self.lock = threading.Lock()
        
        # Alert queues
        self.alerts = deque(maxlen=1000)
        self.alert_callbacks = []
        
        # Detection state
        self.packet_history = deque(maxlen=10000)
        self.connection_history = defaultdict(lambda: deque(maxlen=1000))
        self.dns_history = defaultdict(lambda: deque(maxlen=1000))
        self.beacon_history = defaultdict(lambda: deque(maxlen=1000))
        self.auth_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Thresholds
        self.thresholds = {
            'port_scan': {
                'ports': 20,
                'time_window': 10,
                'severity': 'HIGH'
            },
            'dns_flood': {
                'queries': 50,
                'time_window': 5,
                'severity': 'HIGH'
            },
            'icmp_flood': {
                'packets': 100,
                'time_window': 5,
                'severity': 'MEDIUM'
            },
            'tcp_connections': {
                'connections': 50,
                'time_window': 10,
                'severity': 'MEDIUM'
            },
            'beaconing': {
                'requests': 20,
                'time_window': 60,
                'interval_variance': 5,
                'severity': 'HIGH'
            },
            'brute_force': {
                'attempts': 10,
                'time_window': 60,
                'severity': 'CRITICAL'
            }
        }
        
        self._init_database()
    
    def _init_database(self):
        """Initialize alerts table in database"""
        try:
            conn = self.db._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    packet_count INTEGER,
                    threshold INTEGER,
                    details TEXT,
                    mitre_technique TEXT,
                    timestamp INTEGER NOT NULL,
                    session_id INTEGER,
                    resolved INTEGER DEFAULT 0,
                    resolved_at INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            for col in ['mitre_technique', 'mitre_technique_id', 'mitre_technique_name', 'mitre_tactic', 'detection_type', 'evidence']:
                try:
                    cursor.execute(f'ALTER TABLE alerts ADD COLUMN {col} TEXT')
                except sqlite3.OperationalError:
                    pass

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_mitre_id ON alerts(mitre_technique_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_mitre_tactic ON alerts(mitre_tactic)')
            
            conn.commit()
            logger.info("Alert database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize alert database: {e}")
    
    def start(self):
        """Start the alert engine"""
        if self.running:
            logger.warning("Alert engine already running")
            return
        
        self.running = True
        self.alert_thread = threading.Thread(target=self._run, daemon=True)
        self.alert_thread.start()
        logger.info("Alert engine started")
    
    def stop(self):
        """Stop the alert engine"""
        self.running = False
        if self.alert_thread:
            self.alert_thread.join(timeout=2)
        logger.info("Alert engine stopped")
    
    def _run(self):
        """Main alert processing loop"""
        while self.running:
            try:
                self._process_packets()
                self._check_port_scan()
                self._check_dns_flood()
                self._check_icmp_flood()
                self._check_tcp_connections()
                self._check_beaconing()
                self._check_brute_force()
                self._clean_history()
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Alert engine error: {e}")
                time.sleep(1)
    
    def _process_packets(self):
        """Fetch and process new packets from database"""
        try:
            session_id = self.db.get_current_session_id()
            if not session_id:
                return
            
            query = """
            SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, 
                   protocol, length, tcp_flags
            FROM packets
            WHERE session_id = ? 
                AND timestamp > strftime('%s', 'now', '-1 seconds')
            ORDER BY timestamp DESC
            """
            
            conn = self.db._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id,))
            packets = [dict(row) for row in cur.fetchall()]
            
            for packet in packets:
                packet['session_id'] = session_id
                self.packet_history.append(packet)
                
                key = f"{packet.get('src_ip', '')}:{packet.get('dst_ip', '')}:{packet.get('dst_port', '')}"
                self.connection_history[key].append(packet)
                
                if packet.get('protocol') == 'DNS':
                    self.dns_history[packet.get('src_ip', '')].append(packet)
                
                if packet.get('protocol') in ['HTTP', 'HTTPS']:
                    key = f"{packet.get('src_ip', '')}:{packet.get('dst_ip', '')}"
                    self.beacon_history[key].append(packet)
                
                if packet.get('dst_port') in [21, 22, 23, 3389, 8080, 443] and packet.get('tcp_flags') == 'RST':
                    key = f"{packet.get('src_ip', '')}:{packet.get('dst_ip', '')}"
                    self.auth_history[key].append(packet)
                
        except Exception as e:
            logger.error(f"Error processing packets: {e}")
    
    def _check_port_scan(self):
        """Detect port scanning activity"""
        try:
            threshold = self.thresholds['port_scan']
            time_window = threshold['time_window']
            min_ports = threshold['ports']
            current_time = int(time.time())
            
            src_ips = set()
            for packet in self.packet_history:
                if packet.get('src_ip'):
                    src_ips.add(packet.get('src_ip'))
            
            for src_ip in src_ips:
                ports = set()
                for p in self.packet_history:
                    if p.get('src_ip') == src_ip and current_time - p.get('timestamp', 0) <= time_window:
                        if p.get('dst_port'):
                            ports.add(p.get('dst_port'))
                
                if len(ports) >= min_ports:
                    self._create_alert(
                        alert_type='PORT_SCAN',
                        severity=threshold['severity'],
                        title=f'Port Scan detected from {src_ip}',
                        description=f'Source {src_ip} scanned {len(ports)} ports in {time_window}s',
                        source_ip=src_ip,
                        packet_count=len(ports),
                        threshold=min_ports,
                        details=f'Scanned ports: {sorted(list(ports))[:10]}'
                    )
                    
        except Exception as e:
            logger.error(f"Port scan check error: {e}")
    
    def _check_dns_flood(self):
        """Detect DNS flood attack"""
        try:
            threshold = self.thresholds['dns_flood']
            time_window = threshold['time_window']
            min_queries = threshold['queries']
            current_time = int(time.time())
            
            for src_ip, packets in list(self.dns_history.items()):
                count = sum(1 for p in packets if current_time - p.get('timestamp', 0) <= time_window)
                
                if count >= min_queries:
                    self._create_alert(
                        alert_type='DNS_FLOOD',
                        severity=threshold['severity'],
                        title=f'DNS Flood detected from {src_ip}',
                        description=f'Source {src_ip} sent {count} DNS queries in {time_window}s',
                        source_ip=src_ip,
                        protocol='DNS',
                        packet_count=count,
                        threshold=min_queries
                    )
                    
        except Exception as e:
            logger.error(f"DNS flood check error: {e}")
    
    def _check_icmp_flood(self):
        """Detect ICMP flood attack"""
        try:
            threshold = self.thresholds['icmp_flood']
            time_window = threshold['time_window']
            min_packets = threshold['packets']
            current_time = int(time.time())
            
            icmp_packets = {}
            for packet in self.packet_history:
                if packet.get('protocol') == 'ICMP':
                    src_ip = packet.get('src_ip')
                    if src_ip:
                        if src_ip not in icmp_packets:
                            icmp_packets[src_ip] = []
                        icmp_packets[src_ip].append(packet)
            
            for src_ip, packets in icmp_packets.items():
                count = sum(1 for p in packets if current_time - p.get('timestamp', 0) <= time_window)
                
                if count >= min_packets:
                    self._create_alert(
                        alert_type='ICMP_FLOOD',
                        severity=threshold['severity'],
                        title=f'ICMP Flood detected from {src_ip}',
                        description=f'Source {src_ip} sent {count} ICMP packets in {time_window}s',
                        source_ip=src_ip,
                        protocol='ICMP',
                        packet_count=count,
                        threshold=min_packets
                    )
                    
        except Exception as e:
            logger.error(f"ICMP flood check error: {e}")
    
    def _check_tcp_connections(self):
        """Detect excessive TCP connections"""
        try:
            threshold = self.thresholds['tcp_connections']
            time_window = threshold['time_window']
            min_connections = threshold['connections']
            current_time = int(time.time())
            
            for key, packets in list(self.connection_history.items()):
                count = sum(1 for p in packets if 
                           p.get('protocol') == 'TCP' and 
                           current_time - p.get('timestamp', 0) <= time_window)
                
                if count >= min_connections:
                    parts = key.split(':')
                    src_ip = parts[0] if len(parts) > 0 else 'Unknown'
                    dst_ip = parts[1] if len(parts) > 1 else 'Unknown'
                    dst_port = parts[2] if len(parts) > 2 else 'Unknown'
                    
                    self._create_alert(
                        alert_type='EXCESSIVE_TCP',
                        severity=threshold['severity'],
                        title=f'Excessive TCP Connections from {src_ip}',
                        description=f'Source {src_ip} established {count} TCP connections in {time_window}s',
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        destination_port=int(dst_port) if dst_port and dst_port.isdigit() else None,
                        protocol='TCP',
                        packet_count=count,
                        threshold=min_connections
                    )
                    
        except Exception as e:
            logger.error(f"TCP connections check error: {e}")
    
    def _check_beaconing(self):
        """Detect beaconing activity (C2 communication)"""
        try:
            threshold = self.thresholds['beaconing']
            time_window = threshold['time_window']
            min_requests = threshold['requests']
            current_time = int(time.time())
            
            for key, packets in list(self.beacon_history.items()):
                timestamps = [p.get('timestamp') for p in packets 
                             if current_time - p.get('timestamp', 0) <= time_window]
                timestamps.sort()
                
                if len(timestamps) >= min_requests:
                    intervals = []
                    for i in range(1, len(timestamps)):
                        intervals.append(timestamps[i] - timestamps[i-1])
                    
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        variance = max(intervals) - min(intervals)
                        
                        if variance <= threshold['interval_variance']:
                            parts = key.split(':')
                            src_ip = parts[0] if len(parts) > 0 else 'Unknown'
                            dst_ip = parts[1] if len(parts) > 1 else 'Unknown'
                            
                            self._create_alert(
                                alert_type='BEACONING',
                                severity=threshold['severity'],
                                title=f'Beaconing detected from {src_ip}',
                                description=f'Source {src_ip} has consistent communication pattern (every {avg_interval:.1f}s)',
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                packet_count=len(timestamps),
                                threshold=min_requests,
                                details=f'Avg interval: {avg_interval:.1f}s, Variance: {variance}s'
                            )
                            
        except Exception as e:
            logger.error(f"Beaconing check error: {e}")
    
    def _check_brute_force(self):
        """Detect brute force attacks"""
        try:
            threshold = self.thresholds['brute_force']
            time_window = threshold['time_window']
            min_attempts = threshold['attempts']
            current_time = int(time.time())
            
            for key, packets in list(self.auth_history.items()):
                count = sum(1 for p in packets if current_time - p.get('timestamp', 0) <= time_window)
                
                if count >= min_attempts:
                    parts = key.split(':')
                    src_ip = parts[0] if len(parts) > 0 else 'Unknown'
                    dst_ip = parts[1] if len(parts) > 1 else 'Unknown'
                    
                    self._create_alert(
                        alert_type='BRUTE_FORCE',
                        severity=threshold['severity'],
                        title=f'Brute Force attack from {src_ip}',
                        description=f'Source {src_ip} has {count} failed connection attempts in {time_window}s',
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        packet_count=count,
                        threshold=min_attempts
                    )
                    
        except Exception as e:
            logger.error(f"Brute force check error: {e}")
    
    def _send_email_alert(self, alert):
        """Send email notification for alert"""
        if not ENABLE_EMAIL_ALERTS:
            return
        
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            logger.warning("Email credentials not configured. Skipping email alert.")
            return
        
        try:
            # Check severity threshold
            severity_levels = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            min_level = severity_levels.get(EMAIL_MIN_SEVERITY, 0)
            alert_level = severity_levels.get(alert.severity, 0)
            
            if alert_level < min_level:
                return
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = ALERT_EMAIL_SENDER
            msg['To'] = ', '.join(ALERT_EMAIL_RECIPIENTS)
            msg['Subject'] = f"{ALERT_EMAIL_SUBJECT_PREFIX}{alert.severity} - {alert.title}"
            
            # Email body
            body = f"""
🚨 ALERT DETECTED

═══════════════════════════════════════

Severity:     {alert.severity}
Type:         {alert.alert_type}
Title:        {alert.title}
Description:  {alert.description}

═══════════════════════════════════════

📍 DETAILS:
──────────────────────────────────────
Source IP:      {alert.source_ip or 'N/A'}
Destination IP: {alert.destination_ip or 'N/A'}
Protocol:       {alert.protocol or 'N/A'}
Packet Count:   {alert.packet_count}
Threshold:      {alert.threshold}

⏰ Timestamp:   {datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')}

📝 Additional Details:
{alert.details or 'None'}

═══════════════════════════════════════

To resolve this alert:
1. Visit the Dashboard
2. Click "Resolve" on the alert
or use the API: POST /api/alerts/{{alert.id}}/resolve

═══════════════════════════════════════
Network Traffic Analysis System
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.send_message(msg)
                
            logger.info(f"✅ Email alert sent to {', '.join(ALERT_EMAIL_RECIPIENTS)}")
            
        except Exception as e:
            logger.error(f"❌ Failed to send email alert: {e}")
    
    def _create_alert(self, **kwargs):
        """Create and store a new alert"""
        try:
            # Check if similar alert already exists (deduplication)
            if self._is_duplicate_alert(kwargs):
                return
            
            alert_type = kwargs.get('alert_type', 'UNKNOWN')
            detection_type = kwargs.get('detection_type') or alert_type.lower()
            
            # Retrieve official MITRE ATT&CK mapping from centralized module
            mapping = get_mitre_mapping(alert_type)
            if mapping:
                mitre_tech_id = mapping['technique_id']
                mitre_tech_name = mapping['technique_name']
                mitre_tactic = mapping['tactic']
                mitre_tech = f"{mitre_tech_id} ({mitre_tech_name})"
            else:
                mitre_tech_id = kwargs.get('mitre_technique_id', '')
                mitre_tech_name = kwargs.get('mitre_technique_name', '')
                mitre_tactic = kwargs.get('mitre_tactic', '')
                mitre_tech = kwargs.get('mitre_technique', 'N/A')
            
            evidence = kwargs.get('evidence') or kwargs.get('details', '')

            # Create alert object
            alert = Alert(
                alert_type=alert_type,
                detection_type=detection_type,
                severity=kwargs.get('severity', 'LOW'),
                title=kwargs.get('title', 'Alert'),
                description=kwargs.get('description', ''),
                source_ip=kwargs.get('source_ip', ''),
                destination_ip=kwargs.get('destination_ip', ''),
                source_port=kwargs.get('source_port'),
                destination_port=kwargs.get('destination_port'),
                protocol=kwargs.get('protocol', ''),
                packet_count=kwargs.get('packet_count', 0),
                threshold=kwargs.get('threshold', 0),
                details=kwargs.get('details', ''),
                evidence=evidence,
                mitre_technique=mitre_tech,
                mitre_technique_id=mitre_tech_id,
                mitre_technique_name=mitre_tech_name,
                mitre_tactic=mitre_tactic,
                timestamp=int(time.time()),
                session_id=self.db.get_current_session_id(),
                resolved=False
            )
            
            # Store in database
            self._save_alert(alert)
            
            # Add to queue
            with self.lock:
                self.alerts.append(alert)
            
            # Send email notification
            self._send_email_alert(alert)
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert.to_dict())
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
            
            logger.info(f"[ALERT] Created: {alert.alert_type} - {alert.title} [{alert.mitre_technique_id} / {alert.mitre_tactic}]")
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
    
    def _is_duplicate_alert(self, alert_data):
        """Check if similar alert already exists (within 5 minutes)"""
        try:
            query = """
            SELECT COUNT(*) as count
            FROM alerts
            WHERE alert_type = ? 
                AND source_ip = ?
                AND timestamp > ?
                AND resolved = 0
            """
            
            conn = self.db._get_connection()
            cur = conn.execute(query, (
                alert_data.get('alert_type'),
                alert_data.get('source_ip', ''),
                int(time.time()) - 300
            ))
            result = cur.fetchone()
            
            return result[0] > 0
            
        except Exception as e:
            logger.error(f"Duplicate check error: {e}")
            return False
    
    def _save_alert(self, alert):
        """Save alert to database"""
        try:
            query = """
            INSERT INTO alerts (
                alert_type, detection_type, severity, title, description,
                source_ip, destination_ip, source_port, destination_port,
                protocol, packet_count, threshold, details, evidence,
                mitre_technique, mitre_technique_id, mitre_technique_name, mitre_tactic,
                timestamp, session_id, resolved
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            conn = self.db._get_connection()
            cur = conn.execute(query, (
                alert.alert_type,
                alert.detection_type,
                alert.severity,
                alert.title,
                alert.description,
                alert.source_ip,
                alert.destination_ip,
                alert.source_port,
                alert.destination_port,
                alert.protocol,
                alert.packet_count,
                alert.threshold,
                alert.details,
                alert.evidence or alert.details,
                alert.mitre_technique,
                alert.mitre_technique_id,
                alert.mitre_technique_name,
                alert.mitre_tactic,
                alert.timestamp,
                alert.session_id,
                0
            ))
            alert.id = cur.lastrowid
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
    
    def _clean_history(self):
        """Clean old history data"""
        try:
            current_time = int(time.time())
            keep_seconds = 300
            
            while self.packet_history and current_time - self.packet_history[0].get('timestamp', 0) > keep_seconds:
                self.packet_history.popleft()
                
        except Exception as e:
            logger.error(f"Clean history error: {e}")
    
    def get_alerts(self, limit=100, severity=None, resolved=None, alert_type=None,
                   mitre_technique_id=None, mitre_tactic=None, source_ip=None, detection_type=None):
        """Get alerts from database with flexible filtering"""
        try:
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if severity:
                query += " AND UPPER(severity) = ?"
                params.append(severity.upper())
            
            if resolved is not None:
                query += " AND resolved = ?"
                params.append(1 if resolved else 0)
            
            if alert_type:
                query += " AND UPPER(alert_type) = ?"
                params.append(alert_type.upper())

            if detection_type:
                query += " AND (LOWER(detection_type) = ? OR LOWER(alert_type) = ?)"
                params.append(detection_type.lower())
                params.append(detection_type.lower())

            if mitre_technique_id:
                query += " AND UPPER(mitre_technique_id) = ?"
                params.append(mitre_technique_id.upper())

            if mitre_tactic:
                query += " AND LOWER(mitre_tactic) = ?"
                params.append(mitre_tactic.lower())

            if source_ip:
                query += " AND source_ip LIKE ?"
                params.append(f"%{source_ip}%")
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            conn = self.db._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, params)
            alerts = [dict(row) for row in cur.fetchall()]
            
            for alert in alerts:
                alert['time_local'] = datetime.fromtimestamp(alert['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                if not alert.get('detection_type') and alert.get('alert_type'):
                    alert['detection_type'] = alert['alert_type'].lower()
                # Ensure mapping status is included
                mapping = get_mitre_mapping(alert.get('alert_type', ''))
                alert['mitre_status'] = mapping.get('mapping_status', 'Potential / Suspected') if mapping else 'Potential / Suspected'
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []

    def get_mitre_stats(self):
        """Get real MITRE ATT&CK statistics directly from actual database alert records"""
        try:
            query = """
            SELECT 
                mitre_technique_id,
                mitre_technique_name,
                mitre_tactic,
                detection_type,
                COUNT(*) as detection_count,
                MAX(severity) as severity,
                MAX(timestamp) as last_seen
            FROM alerts
            WHERE mitre_technique_id IS NOT NULL AND mitre_technique_id != '' AND mitre_technique_id != 'N/A'
            GROUP BY mitre_technique_id, mitre_technique_name, mitre_tactic
            ORDER BY detection_count DESC
            """
            conn = self.db._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query)
            results = [dict(row) for row in cur.fetchall()]

            for row in results:
                if row.get('last_seen'):
                    row['last_seen_local'] = datetime.fromtimestamp(row['last_seen']).strftime('%Y-%m-%d %H:%M:%S')
                mapping = get_mitre_mapping(row.get('detection_type', ''))
                row['status'] = mapping.get('mapping_status', 'Potential / Suspected') if mapping else 'Potential / Suspected'

            return results
        except Exception as e:
            logger.error(f"Error getting MITRE stats: {e}")
            return []
    
    def get_alert_stats(self):
        """Get alert statistics"""
        try:
            query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN resolved = 0 THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN resolved = 1 THEN 1 ELSE 0 END) as resolved_count,
                severity,
                COUNT(*) as count
            FROM alerts
            GROUP BY severity
            """
            
            conn = self.db._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query)
            results = [dict(row) for row in cur.fetchall()]
            
            stats = {
                'total': 0,
                'active': 0,
                'resolved': 0,
                'by_severity': {}
            }
            
            for row in results:
                stats['total'] += row['count']
                if row['severity']:
                    stats['by_severity'][row['severity']] = row['count']
                if row['resolved_count'] == 0:
                    stats['active'] += row['count']
                else:
                    stats['resolved'] += row['count']
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting alert stats: {e}")
            return {'total': 0, 'active': 0, 'resolved': 0, 'by_severity': {}}
    
    def resolve_alert(self, alert_id):
        """Mark an alert as resolved"""
        try:
            query = "UPDATE alerts SET resolved = 1, resolved_at = ? WHERE id = ?"
            conn = self.db._get_connection()
            cur = conn.execute(query, (int(time.time()), alert_id))
            conn.commit()
            return cur.rowcount > 0
            
        except Exception as e:
            logger.error(f"Error resolving alert: {e}")
            return False
    
    def resolve_all_alerts(self):
        """Resolve all active alerts"""
        try:
            query = "UPDATE alerts SET resolved = 1, resolved_at = ? WHERE resolved = 0"
            conn = self.db._get_connection()
            cur = conn.execute(query, (int(time.time()),))
            conn.commit()
            return cur.rowcount
            
        except Exception as e:
            logger.error(f"Error resolving all alerts: {e}")
            return 0
    
    def register_callback(self, callback):
        """Register a callback for new alerts"""
        self.alert_callbacks.append(callback)
    
    def update_threshold(self, alert_type, **kwargs):
        """Update detection thresholds"""
        if alert_type in self.thresholds:
            self.thresholds[alert_type].update(kwargs)
            logger.info(f"Updated threshold for {alert_type}: {kwargs}")
            return True
        return False