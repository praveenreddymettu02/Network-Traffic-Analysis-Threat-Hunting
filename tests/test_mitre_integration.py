import unittest
import os
import sys
import tempfile
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import DatabaseManager
from routes.alert_engine import AlertEngine
from engine.mitre_mapping import get_mitre_mapping, get_all_mitre_mappings, MITRE_MAPPINGS
from app import create_app


class TestMitreIntegration(unittest.TestCase):

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.session_id = self.db_manager.create_session()
        self.alert_engine = AlertEngine(db_manager=self.db_manager)
        
        from routes import api
        api.alert_engine = self.alert_engine
        
        app = create_app()
        app.config['TESTING'] = True
        self.client = app.test_client()

    def tearDown(self):
        self.alert_engine.stop()
        os.close(self.db_fd)
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass

    def test_mitre_mapping_config(self):
        """Test centralized MITRE ATT&CK mapping definitions"""
        mappings = get_all_mitre_mappings()
        self.assertIn("PORT_SCAN", mappings)
        self.assertIn("BRUTE_FORCE", mappings)
        
        brute_force_map = get_mitre_mapping("BRUTE_FORCE")
        self.assertIsNotNone(brute_force_map)
        self.assertEqual(brute_force_map["technique_id"], "T1110")
        self.assertEqual(brute_force_map["technique_name"], "Brute Force")
        self.assertEqual(brute_force_map["tactic"], "Credential Access")

    def test_alert_creation_with_mitre_fields(self):
        """Test creating a real alert enriches MITRE ATT&CK fields"""
        self.alert_engine._create_alert(
            alert_type="BRUTE_FORCE",
            severity="CRITICAL",
            title="Brute Force attack from 192.168.1.100",
            description="15 failed SSH connection attempts",
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            packet_count=15,
            threshold=10,
            details="SSH port 22 RST responses received"
        )

        alerts = self.alert_engine.get_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]

        self.assertEqual(alert["alert_type"], "BRUTE_FORCE")
        self.assertEqual(alert["detection_type"], "brute_force")
        self.assertEqual(alert["mitre_technique_id"], "T1110")
        self.assertEqual(alert["mitre_technique_name"], "Brute Force")
        self.assertEqual(alert["mitre_tactic"], "Credential Access")
        self.assertEqual(alert["source_ip"], "192.168.1.100")
        self.assertEqual(alert["severity"], "CRITICAL")

    def test_mitre_stats_aggregation(self):
        """Test real database aggregation for MITRE statistics"""
        self.alert_engine._create_alert(
            alert_type="PORT_SCAN",
            severity="HIGH",
            title="Port Scan detected",
            description="Scanned 25 ports",
            source_ip="10.0.0.5"
        )
        self.alert_engine._create_alert(
            alert_type="PORT_SCAN",
            severity="HIGH",
            title="Port Scan detected",
            description="Scanned 30 ports",
            source_ip="10.0.0.6"
        )

        stats = self.alert_engine.get_mitre_stats()
        self.assertEqual(len(stats), 1)
        stat = stats[0]
        self.assertEqual(stat["mitre_technique_id"], "T1046")
        self.assertEqual(stat["mitre_technique_name"], "Network Service Discovery")
        self.assertEqual(stat["mitre_tactic"], "Discovery")
        self.assertEqual(stat["detection_count"], 2)

    def test_api_mitre_endpoints(self):
        """Test Flask REST API MITRE endpoints"""
        # Create a real alert
        self.alert_engine._create_alert(
            alert_type="BEACONING",
            severity="HIGH",
            title="C2 Beaconing",
            description="Regular interval HTTP communication",
            source_ip="172.16.0.50"
        )

        # GET /api/mitre/stats
        response = self.client.get('/api/mitre/stats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")

        # GET /api/hunting/search
        response = self.client.get('/api/hunting/search?mitre_technique_id=T1071')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(len(data["alerts"]), 1)
        self.assertEqual(data["alerts"][0]["mitre_technique_id"], "T1071")


if __name__ == '__main__':
    unittest.main()
