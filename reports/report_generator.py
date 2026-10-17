from database.db_manager import DatabaseManager


class ReportGenerator:
    def __init__(self, db=None):
        self.db = db or DatabaseManager()

    def generate_protocol_report(self):
        # Query and format
        proto_counts = self.db.get_protocol_counts()
        report = {
            'protocol_counts': proto_counts,
            'total_packets': self.db.get_packet_count()
        }
        return report

    def generate_tcp_report(self):
        sessions = self.db.get_tcp_sessions()
        # Compute additional metrics
        return {'tcp_sessions': sessions}
