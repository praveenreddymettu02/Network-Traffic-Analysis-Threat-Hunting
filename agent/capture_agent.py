#!/usr/bin/env python3
"""
Remote Packet Capture Agent for Network Traffic Analysis & Threat Hunting.

This agent captures real network packets locally (via Scapy / Npcap / libpcap)
or reads PCAP files, and securely streams them to the central backend (e.g. Render).

Usage:
    python agent/capture_agent.py --server https://my-app.onrender.com --key <INGESTION_KEY>
    python agent/capture_agent.py --pcap sample.pcap --server http://127.0.0.1:5000
    python agent/capture_agent.py --dry-run --count 10
"""

import os
import sys
import time
import json
import argparse
import logging
from queue import Queue, Empty
from threading import Thread, Event

# Add project root to path for local imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    import requests
except ImportError:
    print("[ERROR] 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from scapy.all import sniff, rdpcap, Packet
except ImportError:
    print("[ERROR] 'scapy' library required for live capture. Install with: pip install scapy")
    sys.exit(1)

try:
    from parser.packet_parser import PacketParser
    HAS_LOCAL_PARSER = True
except ImportError:
    HAS_LOCAL_PARSER = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('capture_agent')


def extract_fallback_packet(packet):
    """Fallback extraction if parser.packet_parser is unavailable."""
    summary = packet.summary() if hasattr(packet, 'summary') else str(packet)
    proto = 'OTHER'
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    
    # Layer 3
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        proto = 'IP'
    elif packet.haslayer('IPv6'):
        src_ip = packet['IPv6'].src
        dst_ip = packet['IPv6'].dst
        proto = 'IPv6'
    elif packet.haslayer('ARP'):
        proto = 'ARP'
        src_ip = getattr(packet['ARP'], 'psrc', None)
        dst_ip = getattr(packet['ARP'], 'pdst', None)

    # Layer 4 / 7
    if packet.haslayer('TCP'):
        proto = 'TCP'
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
        if dst_port == 80 or src_port == 80:
            proto = 'HTTP'
        elif dst_port == 443 or src_port == 443:
            proto = 'HTTPS'
    elif packet.haslayer('UDP'):
        proto = 'UDP'
        src_port = packet['UDP'].sport
        dst_port = packet['UDP'].dport
        if dst_port == 53 or src_port == 53 or packet.haslayer('DNS'):
            proto = 'DNS'
    elif packet.haslayer('ICMP'):
        proto = 'ICMP'

    raw_hex = bytes(packet).hex() if hasattr(packet, '__bytes__') else None

    dns_data = None
    if packet.haslayer('DNS'):
        try:
            dns = packet['DNS']
            if hasattr(dns, 'qd') and dns.qd:
                qname = getattr(dns.qd, 'qname', b'')
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', errors='ignore').rstrip('.')
                elif isinstance(qname, str):
                    qname = qname.rstrip('.')
                if qname:
                    dns_data = {
                        'domain': qname,
                        'is_response': getattr(dns, 'qr', 0),
                        'query_type': 'A'
                    }
        except Exception:
            pass

    tls_data = None
    if packet.haslayer('TLS_Ext_ServerName'):
        try:
            sni = packet['TLS_Ext_ServerName'].servernames[0].servername
            if isinstance(sni, bytes):
                sni = sni.decode('utf-8', errors='ignore')
            if sni:
                tls_data = {'sni': str(sni)}
        except Exception:
            pass

    res = {
        'timestamp': float(getattr(packet, 'time', time.time())),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': proto,
        'src_port': src_port,
        'dst_port': dst_port,
        'length': len(packet),
        'info': summary,
        'raw_hex': raw_hex[:2000] if raw_hex else None,
        'layers': [layer.__name__ for layer in packet.layers()] if hasattr(packet, 'layers') else []
    }
    if dns_data:
        res['dns'] = dns_data
    if tls_data:
        res['tls'] = tls_data
    return res


def make_json_safe(obj):
    """Recursively convert Scapy / non-primitive objects to JSON-serializable types."""
    if obj is None:
        return None
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()[:500]
    if isinstance(obj, (int, float, str, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items() if k != 'raw'}
    if isinstance(obj, (list, tuple, set)):
        return [make_json_safe(i) for i in obj]
    if hasattr(obj, '__int__'):
        try:
            return int(obj)
        except Exception:
            return str(obj)
    return str(obj)


class RemoteCaptureAgent:
    def __init__(self, server_url, api_key, batch_size=25, interval=2.0, dry_run=False):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.batch_size = max(1, batch_size)
        self.interval = max(0.5, interval)
        self.dry_run = dry_run
        
        self.queue = Queue(maxsize=10000)
        self.stop_event = Event()
        self.parser = PacketParser() if HAS_LOCAL_PARSER else None
        
        self.total_captured = 0
        self.total_ingested = 0
        self.total_errors = 0
        self.sender_thread = None

    def check_connection(self):
        """Verify connectivity and authentication with backend."""
        if self.dry_run:
            logger.info("Dry-run mode active: Skipping remote connection test.")
            return True

        url = f"{self.server_url}/api/ingest/status"
        headers = {'X-API-Key': self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                logger.info(f"Connected to backend! Status: {data.get('status')} | Ingested packets in DB: {data.get('total_packets', 0)}")
                return True
            elif resp.status_code == 401:
                logger.error(f"Authentication failed (HTTP 401): Invalid INGESTION_KEY for {self.server_url}")
                return False
            else:
                logger.warning(f"Unexpected status from {url}: HTTP {resp.status_code} - {resp.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to backend at {self.server_url}: {e}")
            return False

    def parse_packet_data(self, pkt):
        """Convert a Scapy packet into an ingestion payload."""
        fb = extract_fallback_packet(pkt)
        if self.parser:
            try:
                parsed = self.parser.parse(pkt)
                if parsed:
                    if 'raw' in parsed:
                        del parsed['raw']
                    if 'raw_data' in parsed and isinstance(parsed['raw_data'], (bytes, bytearray)):
                        parsed['raw_data'] = parsed['raw_data'].hex()[:500]
                    if fb.get('dns') and not parsed.get('dns'):
                        parsed['dns'] = fb['dns']
                    if fb.get('tls') and not parsed.get('tls'):
                        parsed['tls'] = fb['tls']
                    return parsed
            except Exception as e:
                logger.debug(f"Parser error, falling back: {e}")
        return fb

    def on_packet(self, pkt):
        """Callback for incoming Scapy packet."""
        try:
            self.total_captured += 1
            data = self.parse_packet_data(pkt)
            if self.dry_run:
                logger.info(f"[DRY-RUN] #{self.total_captured} {data.get('protocol')} {data.get('src_ip')} -> {data.get('dst_ip')} ({data.get('length')} B)")
                return

            try:
                self.queue.put_nowait(data)
            except Exception:
                logger.warning("Packet queue full; dropping packet to maintain agent stability.")
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def sender_loop(self):
        """Background worker that flushes batches to backend."""
        batch = []
        last_flush = time.time()

        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                # Wait for items with short timeout
                try:
                    item = self.queue.get(timeout=0.2)
                    batch.append(item)
                except Empty:
                    pass

                now = time.time()
                should_flush = (len(batch) >= self.batch_size) or (batch and (now - last_flush) >= self.interval) or (self.stop_event.is_set() and batch)

                if should_flush:
                    self.flush_batch(batch)
                    batch = []
                    last_flush = time.time()
            except Exception as e:
                logger.error(f"Error in sender loop: {e}")
                time.sleep(0.5)

    def flush_batch(self, batch):
        """Send a batch of packets via POST /api/ingest/packets."""
        if not batch or self.dry_run:
            return

        url = f"{self.server_url}/api/ingest/packets"
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key
        }
        safe_batch = [make_json_safe(p) for p in batch]
        payload = json.dumps({'packets': safe_batch})

        try:
            resp = requests.post(url, data=payload, headers=headers, timeout=15)
            if resp.status_code == 200:
                res_data = resp.json()
                count = res_data.get('ingested', len(batch))
                self.total_ingested += count
                logger.info(f"Ingested {count} packets (Total: {self.total_ingested} / DB: {res_data.get('db_total_packets', '?')})")
            else:
                self.total_errors += 1
                logger.error(f"Failed batch post (HTTP {resp.status_code}): {resp.text[:200]}")
        except requests.exceptions.RequestException as e:
            self.total_errors += 1
            logger.error(f"Network error sending batch to {url}: {e}")

    def run_live(self, interface=None, count=0):
        """Run live sniffing."""
        if not self.dry_run:
            self.sender_thread = Thread(target=self.sender_loop, daemon=True)
            self.sender_thread.start()

        iface_str = interface or "default interface"
        logger.info(f"Starting live packet capture on {iface_str} (Target: {self.server_url})...")
        try:
            sniff_kwargs = {
                'prn': self.on_packet,
                'store': False
            }
            if interface:
                sniff_kwargs['iface'] = interface
            if count and count > 0:
                sniff_kwargs['count'] = count

            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user.")
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
        finally:
            self.stop()

    def run_pcap(self, pcap_path):
        """Ingest offline PCAP file."""
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return

        if not self.dry_run:
            self.sender_thread = Thread(target=self.sender_loop, daemon=True)
            self.sender_thread.start()

        logger.info(f"Reading packets from PCAP file: {pcap_path}...")
        try:
            packets = rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets from PCAP.")
            for pkt in packets:
                self.on_packet(pkt)
        except Exception as e:
            logger.error(f"Error parsing PCAP: {e}")
        finally:
            self.stop()

    def stop(self):
        """Signal sender loop to finish remaining packets and cleanly shut down."""
        logger.info("Stopping capture agent...")
        self.stop_event.set()
        if self.sender_thread and self.sender_thread.is_alive():
            self.sender_thread.join(timeout=10)
        logger.info(f"Agent summary: Captured={self.total_captured}, Ingested={self.total_ingested}, Failed Batches={self.total_errors}")


def main():
    parser = argparse.ArgumentParser(
        description="Remote Packet Capture Agent for Network Traffic Analysis & Threat Hunting",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--server', default=os.getenv('BACKEND_URL', 'http://127.0.0.1:5000'),
                        help="Backend URL (e.g. https://network-traffic.onrender.com)")
    parser.add_argument('--key', default=os.getenv('INGESTION_KEY', 'dev-capture-key-change-in-prod'),
                        help="Ingestion API key for authentication")
    parser.add_argument('--interface', default=None,
                        help="Network interface to sniff (e.g. eth0, Wi-Fi). Auto-detected if omitted.")
    parser.add_argument('--batch-size', type=int, default=25,
                        help="Number of packets per HTTP ingestion batch")
    parser.add_argument('--interval', type=float, default=2.0,
                        help="Seconds to wait before flushing partial batches")
    parser.add_argument('--count', type=int, default=0,
                        help="Total packets to capture (0 = continuous)")
    parser.add_argument('--pcap', default=None,
                        help="Path to a PCAP file to read and ingest instead of live sniffing")
    parser.add_argument('--dry-run', action='store_true',
                        help="Print captured packets to console without sending to backend")

    args = parser.parse_args()

    agent = RemoteCaptureAgent(
        server_url=args.server,
        api_key=args.key,
        batch_size=args.batch_size,
        interval=args.interval,
        dry_run=args.dry_run
    )

    if not args.dry_run:
        if not agent.check_connection():
            logger.error("Backend health/auth check failed. Please verify --server URL and --key.")
            sys.exit(1)

    if args.pcap:
        agent.run_pcap(args.pcap)
    else:
        agent.run_live(interface=args.interface, count=args.count)


if __name__ == '__main__':
    main()
