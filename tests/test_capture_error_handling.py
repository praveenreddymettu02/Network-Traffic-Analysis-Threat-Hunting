"""
Unit tests for capture capability detection, error handling, database persistence, and alert metrics.
"""
import os
import unittest
import tempfile
import shutil

from capture.capture_manager import CaptureManager
from database.db_manager import DatabaseManager
from routes.alert_engine import AlertEngine
import routes.api
from app import create_app
from config import Config


class TestCaptureErrorHandling(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'subfolder', 'test_traffic.db')
        
        # Test that DatabaseManager creates parent subfolder automatically
        Config.DATABASE_PATH = self.db_path
        self.db = DatabaseManager(self.db_path)
        self.orig_api_db = routes.api.db
        routes.api.db = self.db
        
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def tearDown(self):
        routes.api.db = self.orig_api_db
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_database_directory_auto_creation(self):
        """DatabaseManager should create parent directory if missing."""
        self.assertTrue(os.path.exists(os.path.dirname(self.db_path)))
        self.assertTrue(os.path.exists(self.db_path))

    def test_render_environment_capture_disabled(self):
        """CaptureManager should block raw packet sniffing when RENDER environment variable is set."""
        orig_render = os.environ.get('RENDER')
        try:
            os.environ['RENDER'] = 'true'
            cm = CaptureManager(db_manager=self.db)
            can_cap, msg = cm.can_capture()
            self.assertFalse(can_cap)
            self.assertIn("Render", msg)

            # Starting capture should fail safely without crashing
            success, start_msg, session_id = cm.start_capture()
            self.assertFalse(success)
            self.assertIn("Render", start_msg)
            self.assertIsNone(session_id)
            self.assertFalse(cm.running)
            self.assertIsNotNone(cm.last_error)
        finally:
            if orig_render is None:
                os.environ.pop('RENDER', None)
            else:
                os.environ['RENDER'] = orig_render

    def test_api_capture_start_error_response_in_container(self):
        """POST /api/capture/start should return 400 when sniffing is disabled in container."""
        orig_render = os.environ.get('RENDER')
        try:
            os.environ['RENDER'] = 'true'
            res = self.client.post('/api/capture/start', json={'interface': 'eth0'})
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertEqual(data.get('status'), 'error')
            self.assertIn('message', data)
            self.assertIn('Render', data.get('message'))

            # Status should show stopped and reflect last_error
            status_res = self.client.get('/api/capture/status')
            self.assertEqual(status_res.status_code, 200)
            status_data = status_res.get_json()
            self.assertFalse(status_data.get('running'))
            self.assertFalse(status_data.get('can_capture'))
            self.assertIsNotNone(status_data.get('last_error'))
        finally:
            if orig_render is None:
                os.environ.pop('RENDER', None)
            else:
                os.environ['RENDER'] = orig_render

    def test_alert_stats_accuracy(self):
        """AlertEngine.get_alert_stats() should accurately calculate active and resolved alerts."""
        engine = AlertEngine(db_manager=self.db)
        
        # Insert 3 test alerts
        a1 = engine.create_alert(alert_type='PORT_SCAN', severity='high', src_ip='10.0.0.1', message='Port scan 1')
        a2 = engine.create_alert(alert_type='DNS_FLOOD', severity='medium', src_ip='10.0.0.2', message='DNS flood 1')
        a3 = engine.create_alert(alert_type='ICMP_FLOOD', severity='low', src_ip='10.0.0.3', message='ICMP flood 1')
        
        stats = engine.get_alert_stats()
        self.assertEqual(stats.get('total'), 3)
        self.assertEqual(stats.get('active'), 3)
        self.assertEqual(stats.get('resolved'), 0)

        # Resolve one alert
        engine.resolve_alert(a1.id)
        stats_after = engine.get_alert_stats()
        self.assertEqual(stats_after.get('total'), 3)
        self.assertEqual(stats_after.get('active'), 2)
        self.assertEqual(stats_after.get('resolved'), 1)


if __name__ == '__main__':
    unittest.main()
