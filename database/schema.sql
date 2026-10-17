-- ============================================
-- Network Traffic Analysis - Database Schema
-- ============================================
-- This file mirrors the schema in db_manager.py for version control.
-- The application creates tables via db_manager._init_db().
-- This file is reference-only.

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

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre_id ON alerts(mitre_technique_id);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre_tactic ON alerts(mitre_tactic);
