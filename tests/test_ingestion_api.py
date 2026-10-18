"""
Unit and integration tests for secure packet ingestion API.
"""
import os
import unittest
import tempfile
import shutil
import json

from config import Config
from database.db_manager import DatabaseManager
import routes.api
from app import create_app


class TestIngestionAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_traffic.db')
        
        # Override config
        Config.DATABASE_PATH = self.db_path
        Config.INGESTION_KEY = 'test-secret-key-12345'
        
        # Initialize isolated DB and point routes.api.db to it
        self.db = DatabaseManager(self.db_path)
        self.orig_api_db = routes.api.db
        routes.api.db = self.db
        
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def tearDown(self):
        routes.api.db = self.orig_api_db
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ingest_status_unauthorized(self):
        """GET /api/ingest/status should reject requests without valid key."""
        res = self.client.get('/api/ingest/status')
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertEqual(data.get('status'), 'error')

        # Invalid key
        res = self.client.get('/api/ingest/status', headers={'X-API-Key': 'wrong-key'})
        self.assertEqual(res.status_code, 401)

    def test_ingest_status_authorized(self):
        """GET /api/ingest/status should succeed with valid X-API-Key or Bearer token."""
        # Test X-API-Key header
        res = self.client.get('/api/ingest/status', headers={'X-API-Key': 'test-secret-key-12345'})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get('status'), 'ready')
        self.assertIn('total_packets', data)

        # Test Authorization: Bearer token
        res = self.client.get('/api/ingest/status', headers={'Authorization': 'Bearer test-secret-key-12345'})
        self.assertEqual(res.status_code, 200)

    def test_ingest_packets_invalid_payload(self):
        """POST /api/ingest/packets should validate payload format."""
        headers = {'X-API-Key': 'test-secret-key-12345', 'Content-Type': 'application/json'}
        
        # Empty body
        res = self.client.post('/api/ingest/packets', data=json.dumps({}), headers=headers)
        self.assertEqual(res.status_code, 400)

        # 'packets' is not a list
        res = self.client.post('/api/ingest/packets', data=json.dumps({'packets': 'not-a-list'}), headers=headers)
        self.assertEqual(res.status_code, 400)

    def test_ingest_packets_valid(self):
        """POST /api/ingest/packets should insert real packets and update statistics."""
        headers = {'X-API-Key': 'test-secret-key-12345', 'Content-Type': 'application/json'}
        
        sample_packets = [
            {
                'timestamp': 1700000000.0,
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'protocol': 'DNS',
                'src_port': 53000,
                'dst_port': 53,
                'length': 85,
                'info': 'Standard query A example.com',
                'dns_query': 'example.com',
                'dns_type': 'A'
            },
            {
                'timestamp': 1700000001.0,
                'src_ip': '192.168.1.100',
                'dst_ip': '93.184.216.34',
                'protocol': 'HTTP',
                'src_port': 54000,
                'dst_port': 80,
                'length': 250,
                'info': 'GET /index.html HTTP/1.1',
                'http_method': 'GET',
                'http_path': '/index.html',
                'http_host': 'example.com'
            },
            {
                'timestamp': 1700000002.0,
                'src_ip': '10.0.0.5',
                'dst_ip': '192.168.1.1',
                'protocol': 'ICMP',
                'length': 64,
                'info': 'Echo (ping) request'
            }
        ]

        res = self.client.post(
            '/api/ingest/packets',
            data=json.dumps({'packets': sample_packets}),
            headers=headers
        )
        self.assertEqual(res.status_code, 200)
        res_data = res.get_json()
        self.assertEqual(res_data.get('status'), 'success')
        self.assertEqual(res_data.get('ingested'), 3)
        self.assertEqual(res_data.get('db_total_packets'), 3)

        # Verify DB and stats reflect the 3 ingested packets
        stats_res = self.client.get('/api/stats')
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.get_json()
        self.assertEqual(stats.get('total_packets'), 3)
        self.assertEqual(stats.get('dns_count'), 1)
        self.assertEqual(stats.get('http_count'), 1)
        self.assertEqual(stats.get('icmp_count'), 1)

        # Verify packet list returns them
        pkt_res = self.client.get('/api/packets?limit=10')
        self.assertEqual(pkt_res.status_code, 200)
        packets = pkt_res.get_json()
        self.assertEqual(len(packets), 3)


if __name__ == '__main__':
    unittest.main()
