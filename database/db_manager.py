import json
import sqlite3
import time
import threading
from collections import deque

from config import Config
from utils.logger import setup_logger

logger = setup_logger('database')


class DatabaseManager:
    """Thread-safe SQLite database manager with WAL mode and batch inserts."""

    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.current_session_id = None
        self._dns_cache = {}

        # Thread-local storage for connections
        self._local = threading.local()
        self._lock = threading.Lock()

        # Batch insert queue
        self._packet_queue = deque()
        self._batch_size = getattr(Config, 'DB_BATCH_SIZE', 50)
        self._batch_interval = getattr(Config, 'DB_BATCH_INTERVAL', 2.0)
        self._last_flush = time.time()
        self._flush_lock = threading.Lock()

        self._init_db()

    def _get_connection(self):
        """Get a thread-local SQLite connection with WAL mode."""
        conn = getattr(self._local, 'connection', None)
        if conn is not None:
            try:
                # Test if connection is active/open
                conn.total_changes
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                conn = None

        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.connection = conn
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        schema = """
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time INTEGER NOT NULL,
            end_time INTEGER,
            packet_count INTEGER DEFAULT 0,
            bytes_transferred INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active'
        );

        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp INTEGER NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER,
            ttl INTEGER,
            tcp_flags TEXT,
            raw_data BLOB,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS dns_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            domain TEXT NOT NULL,
            query_type TEXT,
            response_code INTEGER,
            is_response INTEGER DEFAULT 0,
            answer_records TEXT,
            ttl INTEGER,
            rcode TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS tcp_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            start_time INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            packet_count INTEGER DEFAULT 0,
            bytes_transferred INTEGER DEFAULT 0,
            syn_count INTEGER DEFAULT 0,
            ack_count INTEGER DEFAULT 0,
            fin_count INTEGER DEFAULT 0,
            rst_count INTEGER DEFAULT 0,
            window_size INTEGER DEFAULT 0,
            duration INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS network_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_count INTEGER DEFAULT 0,
            byte_count INTEGER DEFAULT 0,
            start_time INTEGER,
            last_seen INTEGER,
            duration INTEGER DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            detection_type TEXT,
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
            evidence TEXT,
            mitre_technique TEXT,
            mitre_technique_id TEXT,
            mitre_technique_name TEXT,
            mitre_tactic TEXT,
            timestamp INTEGER NOT NULL,
            session_id INTEGER,
            resolved INTEGER DEFAULT 0,
            resolved_at INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            start_time INTEGER,
            end_time INTEGER,
            packet_count INTEGER DEFAULT 0,
            bytes_transferred INTEGER DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        CREATE TABLE IF NOT EXISTS protocols (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            mac TEXT,
            hostname TEXT,
            first_seen INTEGER,
            last_seen INTEGER,
            packet_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            timestamp INTEGER,
            total_packets INTEGER,
            total_bytes INTEGER,
            protocol_counts TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
        CREATE INDEX IF NOT EXISTS idx_packets_session_ts ON packets(session_id, timestamp);

        CREATE INDEX IF NOT EXISTS idx_dns_session ON dns_logs(session_id);
        CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_logs(domain);
        CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_logs(timestamp);

        CREATE INDEX IF NOT EXISTS idx_tcp_sessions_src ON tcp_sessions(src_ip);
        CREATE INDEX IF NOT EXISTS idx_tcp_sessions_dst ON tcp_sessions(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_tcp_sessions_status ON tcp_sessions(status);
        CREATE INDEX IF NOT EXISTS idx_tcp_sessions_session ON tcp_sessions(session_id);

        CREATE INDEX IF NOT EXISTS idx_flows_session ON network_flows(session_id);
        CREATE INDEX IF NOT EXISTS idx_flows_src ON network_flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_flows_dst ON network_flows(dst_ip);

        -- Alert indexes
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
        CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
        """
        try:
            conn = self._get_connection()
            conn.executescript(schema)
            # Ensure mitre columns exist on existing databases
            for col in ['mitre_technique', 'mitre_technique_id', 'mitre_technique_name', 'mitre_tactic', 'detection_type']:
                try:
                    conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
                except sqlite3.OperationalError:
                    pass  # Column already exists

            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_mitre_id ON alerts(mitre_technique_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_mitre_tactic ON alerts(mitre_tactic)")

            # Clean up stale active sessions from crashed runs
            conn.execute("UPDATE sessions SET status = 'interrupted', end_time = ? WHERE status = 'active'", (int(time.time()),))
            conn.commit()
            logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error("Database init error: %s", e)
            raise

    # =============== SESSION MANAGEMENT ===============
    def create_session(self):
        try:
            query = "INSERT INTO sessions (start_time, status) VALUES (?, 'active')"
            with self._lock:
                conn = self._get_connection()
                cur = conn.cursor()
                cur.execute(query, (int(time.time()),))
                self.current_session_id = cur.lastrowid
                conn.commit()
                logger.info("Created new session: %s", self.current_session_id)
                self._dns_cache.clear()
                return self.current_session_id
        except Exception as e:
            logger.error("Create session error: %s", e)
            return None

    def end_session(self, session_id=None):
        if session_id is None:
            session_id = self.current_session_id

        if not session_id:
            logger.warning("No active session to end")
            return False

        try:
            # Flush any pending packets first
            self._flush_packet_queue()

            query = "SELECT COUNT(*) as packet_count, SUM(length) as bytes_transferred FROM packets WHERE session_id = ?"
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(query, (session_id,))
            result = cur.fetchone()
            packet_count = result[0] or 0
            bytes_transferred = result[1] or 0

            update_query = "UPDATE sessions SET end_time = ?, packet_count = ?, bytes_transferred = ?, status = 'completed' WHERE id = ?"
            cur.execute(update_query, (int(time.time()), packet_count, bytes_transferred, session_id))
            conn.commit()
            logger.info("Ended session %s: %d packets, %d bytes", session_id, packet_count, bytes_transferred)

            if session_id == self.current_session_id:
                self.current_session_id = None
            return True
        except Exception as e:
            logger.error("End session error: %s", e)
            return False

    def get_active_session_id(self):
        """Get the ID of an currently active capture session, if any."""
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM sessions WHERE status = 'active' ORDER BY id DESC LIMIT 1")
            result = cur.fetchone()
            return result[0] if result else None
        except Exception as e:
            logger.error("Get active session error: %s", e)
            return None

    def get_current_session_id(self):
        if self.current_session_id:
            return self.current_session_id

        try:
            conn = self._get_connection()
            cur = conn.cursor()

            # 1. Check for active session
            query = "SELECT id FROM sessions WHERE status = 'active' ORDER BY id DESC LIMIT 1"
            cur.execute(query)
            result = cur.fetchone()
            if result:
                self.current_session_id = result[0]
                return self.current_session_id

            # 2. Prefer the latest session that actually contains packets
            query = """
            SELECT id FROM sessions 
            WHERE packet_count > 0 OR id IN (SELECT DISTINCT session_id FROM packets)
            ORDER BY id DESC LIMIT 1
            """
            cur.execute(query)
            result = cur.fetchone()
            if result:
                self.current_session_id = result[0]
                return result[0]

            # 3. Fallback to latest session in DB
            query = "SELECT id FROM sessions ORDER BY id DESC LIMIT 1"
            cur.execute(query)
            result = cur.fetchone()
            if result:
                return result[0]
        except Exception as e:
            logger.error("Get session error: %s", e)

        return None

    def get_session(self, session_id):
        query = "SELECT id, start_time, end_time, packet_count, bytes_transferred, status FROM sessions WHERE id = ?"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id,))
            result = cur.fetchone()
            conn.row_factory = None
            return dict(result) if result else None
        except Exception as e:
            logger.error("Get session error: %s", e)
            return None

    def get_all_sessions(self, limit=50, offset=0):
        query = "SELECT id, start_time, end_time, packet_count, bytes_transferred, status FROM sessions ORDER BY id DESC LIMIT ? OFFSET ?"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (limit, offset))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get all sessions error: %s", e)
            return []

    def get_session_count(self):
        query = "SELECT COUNT(*) FROM sessions"
        try:
            conn = self._get_connection()
            cur = conn.execute(query)
            return cur.fetchone()[0]
        except Exception as e:
            logger.error("Get session count error: %s", e)
            return 0

    def get_session_packets(self, session_id, limit=50):
        query = "SELECT * FROM packets WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id, limit))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get session packets error: %s", e)
            return []

    def get_session_stats(self, session_id):
        try:
            query = "SELECT COUNT(*) as total_packets, SUM(length) as total_bytes, COUNT(DISTINCT src_ip) as unique_src, COUNT(DISTINCT dst_ip) as unique_dst FROM packets WHERE session_id = ?"
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(query, (session_id,))
            result = cur.fetchone()
            return {
                'session_id': session_id,
                'total_packets': result[0] or 0,
                'total_bytes': result[1] or 0,
                'unique_src': result[2] or 0,
                'unique_dst': result[3] or 0
            }
        except Exception as e:
            logger.error("Get session stats error: %s", e)
            return None

    def get_protocol_counts_for_session(self, session_id):
        query = "SELECT protocol, COUNT(*) as count FROM packets WHERE session_id = ? GROUP BY protocol"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get protocol counts for session error: %s", e)
            return []

    _ALLOWED_IP_COLUMNS = {'src_ip', 'dst_ip'}

    def get_top_ips_for_session(self, session_id, column='src_ip', limit=10):
        if column not in self._ALLOWED_IP_COLUMNS:
            column = 'src_ip'
        query = f"SELECT {column}, COUNT(*) as count FROM packets WHERE session_id = ? AND {column} IS NOT NULL AND {column} != '' AND {column} != '0.0.0.0' AND {column} != '::' GROUP BY {column} ORDER BY count DESC LIMIT ?"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id, limit))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get top IPs for session error: %s", e)
            return []

    def get_traffic_over_time_for_session(self, session_id, interval=60):
        query = "SELECT (timestamp / ?) * ? as time_bucket, COUNT(*) as count, datetime(MIN(timestamp), 'unixepoch', 'localtime') as start_time, datetime(MAX(timestamp), 'unixepoch', 'localtime') as end_time FROM packets WHERE session_id = ? GROUP BY time_bucket ORDER BY time_bucket"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (interval, interval, session_id))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get traffic over time error: %s", e)
            return []

    def get_tcp_sessions_for_session(self, session_id):
        query = "SELECT src_ip, dst_ip, src_port, dst_port, COUNT(*) as packet_count, MIN(timestamp) as start_time, MAX(timestamp) as end_time, SUM(length) as bytes_transferred FROM packets WHERE protocol = 'TCP' AND session_id = ? GROUP BY src_ip, dst_ip, src_port, dst_port"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get TCP sessions for session error: %s", e)
            return []

    def get_dns_queries_for_session(self, session_id):
        query = "SELECT * FROM dns_logs WHERE session_id = ? ORDER BY timestamp DESC LIMIT 100"
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get DNS queries for session error: %s", e)
            return []

    def delete_session(self, session_id):
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM dns_logs WHERE session_id = ?", (session_id,))
            cur.execute("DELETE FROM tcp_sessions WHERE session_id = ?", (session_id,))
            cur.execute("DELETE FROM network_flows WHERE session_id = ?", (session_id,))
            cur.execute("DELETE FROM alerts WHERE session_id = ?", (session_id,))
            cur.execute("DELETE FROM packets WHERE session_id = ?", (session_id,))
            cur.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            conn.commit()
            logger.info("Deleted session %s", session_id)
            return True
        except Exception as e:
            logger.error("Delete session error: %s", e)
            return False

    # =============== PACKETS (BATCHED) ===============
    def insert_packet(self, packet_data):
        """Queue a packet for batch insertion."""
        if not self.current_session_id:
            active = self.get_active_session_id()
            if active:
                self.current_session_id = active
            else:
                self.create_session()

        packet_data['session_id'] = self.current_session_id
        self._packet_queue.append(packet_data)

        # Flush if batch size reached or interval elapsed
        if (len(self._packet_queue) >= self._batch_size or
                time.time() - self._last_flush >= self._batch_interval):
            self._flush_packet_queue()

        return True

    def _flush_packet_queue(self):
        """Flush the packet queue to the database in a single transaction."""
        if not self._packet_queue:
            return

        with self._flush_lock:
            # Drain the queue
            batch = []
            while self._packet_queue:
                try:
                    batch.append(self._packet_queue.popleft())
                except IndexError:
                    break

            if not batch:
                return

            query = """
            INSERT INTO packets (session_id, timestamp, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port,
             protocol, length, ttl, tcp_flags, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            try:
                conn = self._get_connection()
                cur = conn.cursor()
                rows = []
                for pkt in batch:
                    rows.append((
                        pkt.get('session_id'),
                        pkt.get('timestamp'),
                        pkt.get('src_ip'),
                        pkt.get('dst_ip'),
                        pkt.get('src_mac'),
                        pkt.get('dst_mac'),
                        pkt.get('src_port'),
                        pkt.get('dst_port'),
                        pkt.get('protocol'),
                        pkt.get('length'),
                        pkt.get('ttl'),
                        pkt.get('tcp_flags'),
                        pkt.get('raw_data')
                    ))
                cur.executemany(query, rows)
                conn.commit()
                self._last_flush = time.time()
                logger.debug("Flushed %d packets to database", len(rows))
            except Exception as e:
                logger.error("Batch insert failed: %s", e)

    # =============== DNS LOGS ===============
    def insert_dns_log(self, domain, src_ip, dst_ip, query_type=None, is_response=0, answers=None, rcode=None):
        if not self.current_session_id:
            active = self.get_active_session_id()
            if active:
                self.current_session_id = active
            else:
                self.create_session()

        session_id = self.current_session_id
        current_time = time.time()
        cache_key = f"{domain}_{src_ip}_{is_response}"

        if cache_key in self._dns_cache:
            last_time = self._dns_cache[cache_key]
            if current_time - last_time < 2:
                logger.debug("Skipping duplicate DNS: %s", domain)
                return None

        self._dns_cache[cache_key] = current_time

        # Clean old cache entries
        old_keys = [k for k, v in self._dns_cache.items() if current_time - v > 60]
        for k in old_keys:
            del self._dns_cache[k]

        answers_json = json.dumps(answers) if answers else None

        ttl = None
        if answers and len(answers) > 0:
            ttl = answers[0].get('ttl')

        rcode_text = None
        if rcode is not None:
            rcode_map = {0: 'No Error', 1: 'Format Error', 2: 'Server Failure', 3: 'NXDOMAIN', 4: 'Not Implemented', 5: 'Refused'}
            rcode_text = rcode_map.get(rcode, f'Unknown ({rcode})')

        query = """
        INSERT INTO dns_logs (session_id, timestamp, src_ip, dst_ip, domain, query_type, is_response, answer_records, ttl, rcode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute(query, (
                session_id,
                int(current_time),
                src_ip,
                dst_ip,
                domain,
                query_type,
                is_response,
                answers_json,
                ttl,
                rcode_text
            ))
            conn.commit()
            logger.debug("DNS: %s | src=%s | response=%s | answers=%d",
                         domain, src_ip, is_response, len(answers) if answers else 0)
            return cur.lastrowid
        except Exception as e:
            logger.error("Insert DNS log error: %s", e)
            return None

    def get_dns_logs(self, limit=50, session_only=True):
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            result = []

            if session_only:
                session_id = self.current_session_id or self.get_current_session_id()
                if session_id:
                    query = """
                    SELECT id, session_id, timestamp, src_ip, dst_ip, domain, query_type, is_response, answer_records, ttl, rcode,
                           datetime(timestamp, 'unixepoch', 'localtime') as time_local
                    FROM dns_logs WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?
                    """
                    cur = conn.execute(query, (session_id, limit))
                    result = [dict(row) for row in cur.fetchall()]

            # If session_only returned nothing or session_only is False, get latest across all sessions
            if not result:
                query = """
                SELECT id, session_id, timestamp, src_ip, dst_ip, domain, query_type, is_response, answer_records, ttl, rcode,
                       datetime(timestamp, 'unixepoch', 'localtime') as time_local
                FROM dns_logs ORDER BY timestamp DESC LIMIT ?
                """
                cur = conn.execute(query, (limit,))
                result = [dict(row) for row in cur.fetchall()]

            conn.row_factory = None
            for record in result:
                if record.get('answer_records'):
                    try:
                        record['answer_records'] = json.loads(record['answer_records'])
                    except Exception:
                        record['answer_records'] = []
            return result
        except Exception as e:
            logger.error("Get DNS logs error: %s", e)
            return []

    def get_dns_count(self, session_only=True):
        try:
            conn = self._get_connection()
            if session_only:
                session_id = self.current_session_id or self.get_current_session_id()
                if session_id:
                    cur = conn.execute("SELECT COUNT(*) FROM dns_logs WHERE session_id = ?", (session_id,))
                    count = cur.fetchone()[0]
                    if count > 0:
                        return count
            cur = conn.execute("SELECT COUNT(*) FROM dns_logs")
            return cur.fetchone()[0]
        except Exception as e:
            logger.error("Get DNS count error: %s", e)
            return 0

    # =============== TCP SESSIONS ===============
    def upsert_tcp_session(self, session_data):
        """Insert or update TCP session using UPSERT pattern."""
        capture_session_id = session_data.get('session_id', self.current_session_id)
        src_ip = session_data.get('src_ip')
        dst_ip = session_data.get('dst_ip')
        src_port = session_data.get('src_port')
        dst_port = session_data.get('dst_port')

        if not all([src_ip, dst_ip, src_port, dst_port]):
            return None

        try:
            conn = self._get_connection()
            cur = conn.cursor()

            # Check if session exists
            check_query = """
            SELECT id FROM tcp_sessions
            WHERE session_id = ? AND src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ?
            LIMIT 1
            """
            cur.execute(check_query, (capture_session_id, src_ip, dst_ip, src_port, dst_port))
            existing = cur.fetchone()

            if existing:
                # UPDATE existing
                update_query = """
                UPDATE tcp_sessions SET
                    last_seen = ?, packet_count = ?, bytes_transferred = ?,
                    syn_count = ?, ack_count = ?, fin_count = ?, rst_count = ?,
                    window_size = ?, duration = ?, status = ?
                WHERE id = ?
                """
                cur.execute(update_query, (
                    session_data.get('last_seen', int(time.time())),
                    session_data.get('packet_count', 1),
                    session_data.get('bytes', 0),
                    session_data.get('syn_count', 0),
                    session_data.get('ack_count', 0),
                    session_data.get('fin_count', 0),
                    session_data.get('rst_count', 0),
                    session_data.get('window_size', 0),
                    session_data.get('duration', 0),
                    session_data.get('status', 'active'),
                    existing[0]
                ))
                conn.commit()
                return existing[0]
            else:
                # INSERT new
                insert_query = """
                INSERT INTO tcp_sessions
                (session_id, src_ip, dst_ip, src_port, dst_port, start_time, last_seen,
                 packet_count, bytes_transferred, syn_count, ack_count, fin_count,
                 rst_count, window_size, duration, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                cur.execute(insert_query, (
                    capture_session_id,
                    src_ip, dst_ip, src_port, dst_port,
                    session_data.get('start_time', int(time.time())),
                    session_data.get('last_seen', int(time.time())),
                    session_data.get('packet_count', 1),
                    session_data.get('bytes', 0),
                    session_data.get('syn_count', 0),
                    session_data.get('ack_count', 0),
                    session_data.get('fin_count', 0),
                    session_data.get('rst_count', 0),
                    session_data.get('window_size', 0),
                    session_data.get('duration', 0),
                    session_data.get('status', 'active')
                ))
                conn.commit()
                return cur.lastrowid
        except Exception as e:
            logger.error("Upsert TCP session error: %s", e)
            return None

    # Keep legacy method name for backward compatibility
    def insert_tcp_session(self, session_data):
        """Legacy method - redirects to upsert_tcp_session."""
        return self.upsert_tcp_session(session_data)

    def get_tcp_sessions(self, limit=100, status=None):
        """Get TCP sessions for current session, fallback to all sessions if empty."""
        try:
            session_id = self.current_session_id or self.get_current_session_id()
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            result = []

            if session_id:
                query = "SELECT * FROM tcp_sessions WHERE session_id = ?"
                params = [session_id]
                if status:
                    query += " AND status = ?"
                    params.append(status)
                query += " ORDER BY last_seen DESC LIMIT ?"
                params.append(limit)
                cur = conn.execute(query, params)
                result = [dict(row) for row in cur.fetchall()]

            # Fallback to all sessions if none found for current session
            if not result:
                query = "SELECT * FROM tcp_sessions"
                params = []
                if status:
                    query += " WHERE status = ?"
                    params.append(status)
                query += " ORDER BY last_seen DESC LIMIT ?"
                params.append(limit)
                cur = conn.execute(query, params)
                result = [dict(row) for row in cur.fetchall()]

            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get TCP sessions error: %s", e)
            return []

    def get_tcp_session_stats(self):
        """Get TCP session statistics."""
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            if session_id:
                query = """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'active' OR status = 'established' OR status = 'syn_sent' THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closed,
                    SUM(CASE WHEN status = 'reset' THEN 1 ELSE 0 END) as reset
                FROM tcp_sessions
                WHERE session_id = ?
                """
                cur = conn.execute(query, (session_id,))
                result = cur.fetchone()
                if result and result[0] and result[0] > 0:
                    return {
                        'total': result[0] or 0,
                        'active': result[1] or 0,
                        'closed': result[2] or 0,
                        'reset': result[3] or 0
                    }

            query_all = """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'active' OR status = 'established' OR status = 'syn_sent' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closed,
                SUM(CASE WHEN status = 'reset' THEN 1 ELSE 0 END) as reset
            FROM tcp_sessions
            """
            cur = conn.execute(query_all)
            result = cur.fetchone()
            return {
                'total': result[0] or 0,
                'active': result[1] or 0,
                'closed': result[2] or 0,
                'reset': result[3] or 0
            }
        except Exception as e:
            logger.error("Get TCP session stats error: %s", e)
            return {'total': 0, 'active': 0, 'closed': 0, 'reset': 0}

    # =============== NETWORK FLOWS ===============
    def upsert_network_flow(self, flow_data):
        """Insert or update network flow."""
        session_id = flow_data.get('session_id', self.current_session_id)
        src_ip = flow_data.get('src_ip')
        dst_ip = flow_data.get('dst_ip')
        src_port = flow_data.get('src_port')
        dst_port = flow_data.get('dst_port')
        protocol = flow_data.get('protocol')

        try:
            conn = self._get_connection()
            cur = conn.cursor()

            check = """
            SELECT id, packet_count, byte_count FROM network_flows
            WHERE session_id = ? AND src_ip = ? AND dst_ip = ? AND src_port = ? AND dst_port = ? AND protocol = ?
            LIMIT 1
            """
            cur.execute(check, (session_id, src_ip, dst_ip, src_port, dst_port, protocol))
            existing = cur.fetchone()

            now = int(time.time())
            if existing:
                update = """
                UPDATE network_flows SET
                    packet_count = ?, byte_count = ?, last_seen = ?,
                    duration = last_seen - start_time
                WHERE id = ?
                """
                new_packets = (existing[1] or 0) + flow_data.get('packet_count', 1)
                new_bytes = (existing[2] or 0) + flow_data.get('byte_count', 0)
                cur.execute(update, (new_packets, new_bytes, now, existing[0]))
            else:
                insert = """
                INSERT INTO network_flows (session_id, src_ip, dst_ip, src_port, dst_port, protocol,
                    packet_count, byte_count, start_time, last_seen, duration)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """
                cur.execute(insert, (session_id, src_ip, dst_ip, src_port, dst_port, protocol,
                                     flow_data.get('packet_count', 1), flow_data.get('byte_count', 0), now, now))
            conn.commit()
        except Exception as e:
            logger.error("Upsert network flow error: %s", e)

    def get_top_flows(self, limit=20):
        """Get top network flows by byte count."""
        session_id = self.current_session_id or self.get_current_session_id()
        if not session_id:
            return []
        query = """
        SELECT * FROM network_flows WHERE session_id = ?
        ORDER BY byte_count DESC LIMIT ?
        """
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, (session_id, limit))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get top flows error: %s", e)
            return []

    # =============== CURRENT SESSION QUERIES ===============
    def get_packet_count(self):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            if session_id:
                cur = conn.execute("SELECT COUNT(*) FROM packets WHERE session_id = ?", (session_id,))
                count = cur.fetchone()[0]
                if count > 0:
                    return count
            cur = conn.execute("SELECT COUNT(*) FROM packets")
            return cur.fetchone()[0]
        except Exception as e:
            logger.error("Get packet count error: %s", e)
            return 0

    def get_protocol_counts(self):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            if session_id:
                cur = conn.execute("SELECT protocol, COUNT(*) as count FROM packets WHERE session_id = ? GROUP BY protocol", (session_id,))
                result = [dict(row) for row in cur.fetchall()]
                if result:
                    conn.row_factory = None
                    return result
            cur = conn.execute("SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol")
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get protocol counts error: %s", e)
            return []

    def get_top_ips(self, column='src_ip', limit=10):
        if column not in self._ALLOWED_IP_COLUMNS:
            column = 'src_ip'
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            if session_id:
                query = f"SELECT {column}, COUNT(*) as count FROM packets WHERE session_id = ? AND {column} IS NOT NULL AND {column} != '' AND {column} != '0.0.0.0' AND {column} != '::' GROUP BY {column} ORDER BY count DESC LIMIT ?"
                cur = conn.execute(query, (session_id, limit))
                result = [dict(row) for row in cur.fetchall()]
                if result:
                    conn.row_factory = None
                    return result
            query = f"SELECT {column}, COUNT(*) as count FROM packets WHERE {column} IS NOT NULL AND {column} != '' AND {column} != '0.0.0.0' AND {column} != '::' GROUP BY {column} ORDER BY count DESC LIMIT ?"
            cur = conn.execute(query, (limit,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get top IPs error: %s", e)
            return []

    def get_top_ports(self, limit=10):
        """Get top destination ports."""
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            if session_id:
                query = """
                SELECT dst_port as port, COUNT(*) as count, protocol
                FROM packets WHERE session_id = ? AND dst_port IS NOT NULL AND dst_port > 0
                GROUP BY dst_port ORDER BY count DESC LIMIT ?
                """
                cur = conn.execute(query, (session_id, limit))
                result = [dict(row) for row in cur.fetchall()]
                if result:
                    conn.row_factory = None
                    return result
            query = """
            SELECT dst_port as port, COUNT(*) as count, protocol
            FROM packets WHERE dst_port IS NOT NULL AND dst_port > 0
            GROUP BY dst_port ORDER BY count DESC LIMIT ?
            """
            cur = conn.execute(query, (limit,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get top ports error: %s", e)
            return []

    def get_traffic_over_time(self, interval=60):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            if session_id:
                query = "SELECT (timestamp / ?) * ? as time_bucket, COUNT(*) as count, datetime(MIN(timestamp), 'unixepoch', 'localtime') as start_time, datetime(MAX(timestamp), 'unixepoch', 'localtime') as end_time FROM packets WHERE session_id = ? GROUP BY time_bucket ORDER BY time_bucket"
                cur = conn.execute(query, (interval, interval, session_id))
                result = [dict(row) for row in cur.fetchall()]
                if result:
                    conn.row_factory = None
                    return result
            query = "SELECT (timestamp / ?) * ? as time_bucket, COUNT(*) as count, datetime(MIN(timestamp), 'unixepoch', 'localtime') as start_time, datetime(MAX(timestamp), 'unixepoch', 'localtime') as end_time FROM packets GROUP BY time_bucket ORDER BY time_bucket"
            cur = conn.execute(query, (interval,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get traffic over time error: %s", e)
            return []

    def get_tcp_sessions_old(self):
        """Legacy method - use get_tcp_sessions instead."""
        return self.get_tcp_sessions()

    def get_dns_queries(self):
        return self.get_dns_logs(50, session_only=False)

    def get_recent_packets(self, limit=50):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            if session_id:
                query = "SELECT * FROM packets WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?"
                cur = conn.execute(query, (session_id, limit))
                result = [dict(row) for row in cur.fetchall()]
                if result:
                    conn.row_factory = None
                    return result
            query = "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?"
            cur = conn.execute(query, (limit,))
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get recent packets error: %s", e)
            return []

    def get_traffic_by_hour(self):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            result = []
            if session_id:
                query = """
                SELECT strftime('%Y-%m-%d %H:00:00', datetime(timestamp, 'unixepoch', 'localtime')) as time_bucket,
                       strftime('%H:00', datetime(timestamp, 'unixepoch', 'localtime')) as hour_label,
                       COUNT(*) as count, SUM(length) as bytes
                FROM packets WHERE session_id = ?
                GROUP BY time_bucket ORDER BY time_bucket DESC LIMIT 168
                """
                cur = conn.execute(query, (session_id,))
                result = [dict(row) for row in cur.fetchall()]

            if not result:
                query = """
                SELECT strftime('%Y-%m-%d %H:00:00', datetime(timestamp, 'unixepoch', 'localtime')) as time_bucket,
                       strftime('%H:00', datetime(timestamp, 'unixepoch', 'localtime')) as hour_label,
                       COUNT(*) as count, SUM(length) as bytes
                FROM packets
                GROUP BY time_bucket ORDER BY time_bucket DESC LIMIT 168
                """
                cur = conn.execute(query)
                result = [dict(row) for row in cur.fetchall()]

            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get traffic by hour error: %s", e)
            return []

    def get_traffic_by_day(self):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            result = []
            if session_id:
                query = """
                SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch', 'localtime')) as date,
                       COUNT(*) as count, SUM(length) as bytes, COUNT(DISTINCT src_ip) as unique_hosts
                FROM packets WHERE session_id = ?
                GROUP BY date ORDER BY date DESC LIMIT 90
                """
                cur = conn.execute(query, (session_id,))
                result = [dict(row) for row in cur.fetchall()]

            if not result:
                query = """
                SELECT strftime('%Y-%m-%d', datetime(timestamp, 'unixepoch', 'localtime')) as date,
                       COUNT(*) as count, SUM(length) as bytes, COUNT(DISTINCT src_ip) as unique_hosts
                FROM packets
                GROUP BY date ORDER BY date DESC LIMIT 90
                """
                cur = conn.execute(query)
                result = [dict(row) for row in cur.fetchall()]

            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get traffic by day error: %s", e)
            return []

    def get_traffic_by_week(self):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            result = []
            if session_id:
                query = """
                SELECT strftime('%Y-W%W', datetime(timestamp, 'unixepoch', 'localtime')) as week,
                       MIN(date(datetime(timestamp, 'unixepoch', 'localtime'))) as start_date,
                       MAX(date(datetime(timestamp, 'unixepoch', 'localtime'))) as end_date,
                       COUNT(*) as count, SUM(length) as bytes, COUNT(DISTINCT src_ip) as unique_hosts
                FROM packets WHERE session_id = ?
                GROUP BY week ORDER BY week DESC LIMIT 52
                """
                cur = conn.execute(query, (session_id,))
                result = [dict(row) for row in cur.fetchall()]

            if not result:
                query = """
                SELECT strftime('%Y-W%W', datetime(timestamp, 'unixepoch', 'localtime')) as week,
                       MIN(date(datetime(timestamp, 'unixepoch', 'localtime'))) as start_date,
                       MAX(date(datetime(timestamp, 'unixepoch', 'localtime'))) as end_date,
                       COUNT(*) as count, SUM(length) as bytes, COUNT(DISTINCT src_ip) as unique_hosts
                FROM packets
                GROUP BY week ORDER BY week DESC LIMIT 52
                """
                cur = conn.execute(query)
                result = [dict(row) for row in cur.fetchall()]

            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get traffic by week error: %s", e)
            return []

    def get_traffic_by_month(self):
        session_id = self.current_session_id or self.get_current_session_id()
        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            result = []
            if session_id:
                query = """
                SELECT strftime('%Y-%m', datetime(timestamp, 'unixepoch', 'localtime')) as month,
                       COUNT(*) as count, SUM(length) as bytes, COUNT(DISTINCT src_ip) as unique_hosts
                FROM packets WHERE session_id = ?
                GROUP BY month ORDER BY month DESC LIMIT 24
                """
                cur = conn.execute(query, (session_id,))
                result = [dict(row) for row in cur.fetchall()]

            if not result:
                query = """
                SELECT strftime('%Y-%m', datetime(timestamp, 'unixepoch', 'localtime')) as month,
                       COUNT(*) as count, SUM(length) as bytes, COUNT(DISTINCT src_ip) as unique_hosts
                FROM packets
                GROUP BY month ORDER BY month DESC LIMIT 24
                """
                cur = conn.execute(query)
                result = [dict(row) for row in cur.fetchall()]

            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Get traffic by month error: %s", e)
            return []

    # =============== RETENTION / CLEANUP ===============
    def cleanup_old_data(self, days=None):
        """Remove data older than N days."""
        if days is None:
            days = getattr(Config, 'RETENTION_DAYS', 30)
        cutoff = int(time.time()) - (days * 86400)
        try:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM dns_logs WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM tcp_sessions WHERE start_time < ?", (cutoff,))
            cur.execute("DELETE FROM network_flows WHERE start_time < ?", (cutoff,))
            cur.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM sessions WHERE start_time < ? AND status = 'completed'", (cutoff,))
            conn.commit()
            logger.info("Cleaned up data older than %d days", days)
        except Exception as e:
            logger.error("Cleanup error: %s", e)

    # =============== SEARCH ===============
    def search_packets(self, src_ip=None, dst_ip=None, protocol=None, src_port=None, dst_port=None, limit=100):
        """Search packets with parameterized queries."""
        conditions = []
        params = []

        if src_ip:
            conditions.append("src_ip LIKE ?")
            params.append(f"%{src_ip}%")
        if dst_ip:
            conditions.append("dst_ip LIKE ?")
            params.append(f"%{dst_ip}%")
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol)
        if src_port:
            conditions.append("src_port = ?")
            params.append(int(src_port))
        if dst_port:
            conditions.append("dst_port = ?")
            params.append(int(dst_port))

        where = " AND ".join(conditions) if conditions else "1=1"
        query = f"""
        SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port,
               protocol, length, tcp_flags,
               datetime(timestamp, 'unixepoch', 'localtime') as time_local
        FROM packets WHERE {where}
        ORDER BY timestamp DESC LIMIT ?
        """
        params.append(limit)

        try:
            conn = self._get_connection()
            conn.row_factory = sqlite3.Row
            cur = conn.execute(query, params)
            result = [dict(row) for row in cur.fetchall()]
            conn.row_factory = None
            return result
        except Exception as e:
            logger.error("Search packets error: %s", e)
            return []