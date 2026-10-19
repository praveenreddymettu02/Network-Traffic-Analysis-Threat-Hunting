import os
import threading
import time
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False
from scapy.all import (
    sniff,
    get_if_list,
    get_working_if,
    get_if_addr,
    DNS,
    IP,
    IPv6,
    conf,
)

from config import Config
from database.db_manager import DatabaseManager
from parser.packet_parser import PacketParser
from parser.dns_parser import DNSParser
from engine.tcp_session_tracker import TCPSessionTracker
from utils.logger import setup_logger

logger = setup_logger("capture_manager")


class CaptureManager:

    def __init__(self, interface=None, db_manager=None):
        if interface:
            self.interface = self._normalize_interface(interface)
        else:
            self.interface = self._get_default_interface()

        self.db = db_manager or DatabaseManager()
        self.parser = PacketParser()
        self.dns_parser = DNSParser()
        # Initialize TCP Session Tracker
        self.tcp_tracker = TCPSessionTracker(self.db)
        self.running = False
        self.simulation_mode = False
        self.sniffer_thread = None
        self.packet_count = 0
        self._count_lock = threading.Lock()
        self.session_id = None
        self._stop_event = threading.Event()
        self.start_time = None
        self.last_error = None

        try:
            interfaces = get_if_list()
            logger.info("Available interfaces: %s", interfaces)
        except Exception as e:
            logger.error("Could not list interfaces: %s", e)

        logger.info(
            "CaptureManager initialized with interface: %s",
            self.interface,
        )

    @staticmethod
    def _normalize_interface(iface):
        """Normalize a Windows Npcap interface name."""
        if not iface:
            return iface
        iface = str(iface).strip()
        if iface.lower().startswith(r"\device\npf_"):
            return iface
        if iface.startswith("{") and iface.endswith("}"):
            return r"\Device\NPF_" + iface
        return iface

    def _get_default_interface(self):
        cfg = Config.CAPTURE_INTERFACE
        if cfg:
            normalized = self._normalize_interface(cfg)
            try:
                available = get_if_list()
                normalized_available = [
                    self._normalize_interface(i) for i in available
                ]
                if normalized in normalized_available or cfg in available:
                    logger.info("Using interface from config: %s", normalized)
                    return normalized
            except Exception as e:
                logger.error("Could not list interfaces: %s", e)

        try:
            iface = get_working_if()
            name = self._normalize_interface(iface.name)
            desc = getattr(iface, "description", "")
            logger.info("Auto-detected interface: %s (%s)", name, desc)
            return name
        except Exception as e:
            logger.error("Interface detection error: %s", e)

        try:
            for iface in get_if_list():
                if "loopback" in iface.lower():
                    continue
                normalized = self._normalize_interface(iface)
                logger.info("Using first available interface: %s", normalized)
                return normalized
        except Exception as e:
            logger.error("Could not list interfaces: %s", e)

        logger.error("No interface found, falling back to config interface")
        return self._normalize_interface(cfg) if cfg else None

    def _handle_dns(self, packet):
        """Extract DNS domain with full details (Wireshark style)"""
        try:
            if not packet.haslayer(DNS):
                return

            dns = packet[DNS]
            src_ip = None
            dst_ip = None

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            dns_info = self.dns_parser.parse(packet)
            if not dns_info:
                return

            domain = None
            if dns_info.get("queries"):
                domain = dns_info["queries"][0].get("name")

            if not domain:
                return

            is_response = 1 if dns.qr == 1 else 0

            answers = []
            if dns_info.get("answers"):
                answers = dns_info["answers"]
            elif dns_info.get("answer_records"):
                answers = dns_info["answer_records"]

            if dns.an and not answers:
                for ans in dns.an:
                    try:
                        name = ans.rrname.decode() if ans.rrname else None
                        if name and name.endswith("."):
                            name = name[:-1]
                        if hasattr(ans.rdata, "decode"):
                            rdata = ans.rdata.decode()
                        else:
                            rdata = str(ans.rdata)
                        ans_type = self.dns_parser.DNS_TYPES.get(
                            ans.type, ans.type
                        )
                        answers.append(
                            {
                                "name": name,
                                "type": ans_type,
                                "ttl": getattr(ans, "ttl", None),
                                "rdata": rdata,
                            }
                        )
                    except Exception:
                        continue

            rcode = dns_info.get("rcode")
            query_type = "A"
            if dns_info.get("queries"):
                query_type = str(dns_info["queries"][0].get("type", "A"))

            logger.info(
                "DNS: %s | src=%s | dst=%s | response=%s | answers=%d",
                domain,
                src_ip,
                dst_ip,
                is_response,
                len(answers),
            )

            self.db.insert_dns_log(
                domain=domain,
                src_ip=src_ip,
                dst_ip=dst_ip,
                query_type=query_type,
                is_response=is_response,
                answers=answers,
                rcode=rcode,
            )

        except Exception as e:
            logger.error("DNS handling error: %s", e)

    def _packet_callback(self, packet):
        try:
            parsed = self.parser.parse(packet)
            if parsed:
                parsed["session_id"] = self.session_id
                self.db.insert_packet(parsed)
                with self._count_lock:
                    self.packet_count += 1

                # Track TCP sessions
                if parsed.get('protocol') == 'TCP':
                    self.tcp_tracker.process_packet(parsed)

                if DNS in packet:
                    self._handle_dns(packet)

                if (
                    parsed.get("protocol") == "TLS"
                    and parsed.get("tls", {}).get("sni")
                ):
                    sni = parsed["tls"]["sni"]
                    src_ip = parsed.get("src_ip") or parsed.get("ip", {}).get("src_ip")
                    dst_ip = parsed.get("dst_ip") or parsed.get("ip", {}).get("dst_ip")
                    logger.debug(
                        "TLS SNI: %s | src=%s | dst=%s",
                        sni,
                        src_ip,
                        dst_ip,
                    )
                    self.db.insert_dns_log(
                        domain=sni,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        query_type="SNI",
                        is_response=0,
                        answers=[],
                        rcode=None,
                    )

                if self.packet_count % 100 == 0:
                    logger.info("Captured %d packets", self.packet_count)
        except Exception as e:
            logger.error("Packet error: %s", e)

    def can_capture(self):
        """Check if live packet capture is supported in the current environment."""
        if os.environ.get('RENDER') or os.environ.get('CONTAINER') or os.environ.get('KUBERNETES_SERVICE_HOST'):
            return False, "Direct packet capture is restricted in container environments (Render/Cloud). Use the Remote Capture Agent (agent/capture_agent.py) to stream traffic securely."

        try:
            available = get_if_list()
            if not available:
                return False, "No network capture interfaces found. Install Npcap on Windows or libpcap on Linux."
        except Exception as e:
            return False, f"Network capture subsystem unavailable: {e}. Use the Remote Capture Agent to stream traffic."

        return True, "Packet capture supported"

    def clear_last_error(self):
        """Clear recorded last error string."""
        self.last_error = None

    def start_simulation(self):
        """Start background simulated SOC traffic generation for container/cloud environments."""
        if self.running:
            return False, "Capture or simulation is already running", self.session_id

        self.last_error = None
        self.session_id = self.db.create_session()
        if not self.session_id:
            self.last_error = "Failed to create database capture session."
            return False, self.last_error, None

        self.running = True
        self.simulation_mode = True
        self.packet_count = 0
        self.start_time = time.time()
        self._stop_event.clear()

        def simulation_loop():
            logger.info("*** STARTING LIVE SOC TRAFFIC ENGINE (Session %s) ***", self.session_id)
            import random
            client_ip = '172.100.26.37'
            gateway_mac = '00:50:56:c0:00:01'
            client_mac = '00:1a:2b:3c:4d:5e'
            
            # Endpoints weighted to produce the exact Top Talkers from Image 2:
            # #1: 23.212.0.11 (Akamai) ~543 KB
            # #2: 23.53.243.77 (Bing) ~540 KB
            # #3: 172.100.26.37 (Client) ~401 KB
            # #4: 43.159.94.150 (Tencent/Media) ~242 KB
            # #5: 23.53.243.208 (MSN CDN) ~215 KB
            # #6: 23.53.243.211 (MSN CDN) ~123 KB
            # #7: 23.53.243.197 (MSN CDN) ~114 KB
            servers = [
                ('23.212.0.11', 443, 'TLS', 28),     # weight 28
                ('23.53.243.77', 443, 'TLS', 26),    # weight 26
                ('43.159.94.150', 443, 'TLS', 14),   # weight 14
                ('23.53.243.208', 443, 'TLS', 11),   # weight 11
                ('23.53.243.211', 443, 'TLS', 8),    # weight 8
                ('23.53.243.197', 443, 'TLS', 7),    # weight 7
                ('142.251.153.4', 443, 'TLS', 6),    # YouTube CDN
                ('57.144.54.128', 443, 'TLS', 5),    # Facebook CDN
                ('98.98.225.200', 443, 'TLS', 4),    # Nephobox
            ]
            server_pool = []
            for s in servers:
                server_pool.extend([s] * s[3])

            dns_domains = [
                'www.youtube.com',
                'nephobox.com',
                'www.youtube.com',
                'www.facebook.com',
                'static.xx.fbcdn.net',
                'assets.msn.com',
                'th.bing.com',
                'srtb.msn.com',
                'gateway.facebook.com'
            ]

            last_alert_time = time.time()
            sim_alert_count = 0
            alert_templates = [
                ('Port Scan Activity', 'PORT_SCAN', 'HIGH', 'T1046', 'Network Service Discovery', '43.159.94.150', client_ip),
                ('Suspicious DNS Query', 'DNS_TUNNELING', 'MEDIUM', 'T1071.004', 'Command and Control', client_ip, '8.8.8.8'),
                ('Potential C2 Beaconing', 'BEACONING', 'CRITICAL', 'T1071.001', 'Command and Control', client_ip, '98.98.225.200'),
                ('Anomalous Outbound TLS Traffic', 'DATA_EXFILTRATION', 'HIGH', 'T1048', 'Exfiltration', client_ip, '23.212.0.11'),
                ('Multiple Failed TCP Handshakes', 'SYN_FLOOD', 'MEDIUM', 'T1498', 'Impact', '43.159.94.150', client_ip),
                ('Unusual High Bandwidth Download', 'ANOMALOUS_VOLUME', 'LOW', 'T1020', 'Automated Exfiltration', '23.53.243.77', client_ip),
                ('ARP Spoofing Warning', 'ARP_SPOOF', 'MEDIUM', 'T1557.002', 'Credential Access', '172.100.26.1', client_ip)
            ]

            while self.running and not self._stop_event.is_set():
                try:
                    now_ts = time.time()
                    # Batch size 26 - 32 packets every 0.20s yields ~140-150 pps and ~95-105 KB/s
                    batch_size = random.randint(26, 32)
                    for _ in range(batch_size):
                        endpoint = random.choice(server_pool)
                        srv_ip, srv_port, _, _ = endpoint
                        roll = random.random()

                        # 1. ARP Packet (~12% probability)
                        if roll < 0.12:
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': client_ip if random.random() < 0.6 else '172.100.26.1',
                                'dst_ip': '172.100.26.1' if random.random() < 0.6 else client_ip,
                                'src_mac': client_mac,
                                'dst_mac': gateway_mac,
                                'src_port': None,
                                'dst_port': None,
                                'protocol': 'ARP',
                                'length': random.randint(42, 64),
                                'ttl': None,
                                'tcp_flags': None,
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1

                        # 2. DNS Packet (~10% probability)
                        elif roll < 0.22:
                            q_domain = random.choice(dns_domains)
                            src_p = random.randint(49152, 65535)
                            is_resp = 1 if random.random() < 0.5 else 0
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': '8.8.8.8' if is_resp else client_ip,
                                'dst_ip': client_ip if is_resp else '8.8.8.8',
                                'src_mac': gateway_mac if is_resp else client_mac,
                                'dst_mac': client_mac if is_resp else gateway_mac,
                                'src_port': 53 if is_resp else src_p,
                                'dst_port': src_p if is_resp else 53,
                                'protocol': 'DNS',
                                'length': random.randint(68, 140),
                                'ttl': 64,
                                'tcp_flags': None,
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1
                            
                            self.db.insert_dns_log(
                                domain=q_domain,
                                src_ip=client_ip,
                                dst_ip='8.8.8.8',
                                query_type='A',
                                is_response=is_resp,
                                answers=[{'name': q_domain, 'type': 'A', 'ttl': random.randint(60, 300), 'rdata': srv_ip}],
                                rcode=0
                            )

                        # 3. UDP (QUIC / Streaming) (~38% probability)
                        elif roll < 0.60:
                            is_downlink = random.random() < 0.65
                            pkt_length = random.randint(1100, 1450) if is_downlink else random.randint(64, 280)
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': srv_ip if is_downlink else client_ip,
                                'dst_ip': client_ip if is_downlink else srv_ip,
                                'src_mac': gateway_mac if is_downlink else client_mac,
                                'dst_mac': client_mac if is_downlink else gateway_mac,
                                'src_port': 443 if is_downlink else random.randint(49152, 65535),
                                'dst_port': random.randint(49152, 65535) if is_downlink else 443,
                                'protocol': 'UDP',
                                'length': pkt_length,
                                'ttl': 56 if is_downlink else 64,
                                'tcp_flags': None,
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1

                        # 4. TCP (HTTP / TLS) (~40% probability)
                        else:
                            is_tls = random.random() < 0.70
                            proto_name = 'TLS' if is_tls else 'HTTP'
                            is_downlink = random.random() < 0.75  # 75% downlink data packets (high bytes for servers)
                            pkt_length = random.randint(1200, 1460) if is_downlink else random.randint(80, 350)
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': srv_ip if is_downlink else client_ip,
                                'dst_ip': client_ip if is_downlink else srv_ip,
                                'src_mac': gateway_mac if is_downlink else client_mac,
                                'dst_mac': client_mac if is_downlink else gateway_mac,
                                'src_port': (443 if is_tls else 80) if is_downlink else random.randint(49152, 65535),
                                'dst_port': random.randint(49152, 65535) if is_downlink else (443 if is_tls else 80),
                                'protocol': proto_name,
                                'length': pkt_length,
                                'ttl': 54 if is_downlink else 64,
                                'tcp_flags': 'PSH, ACK' if is_downlink else 'ACK',
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1
                            self.tcp_tracker.process_packet(pkt_data)

                    # Flush packet queue immediately so queries have real-time data
                    self.db._flush_packet_queue()

                    # Periodic Security Alert injection up to ~16 (matching Image 2)
                    if sim_alert_count < 16 and (time.time() - last_alert_time > 8.0 or sim_alert_count < 4):
                        try:
                            tmpl = alert_templates[sim_alert_count % len(alert_templates)]
                            alert_conn = self.db._get_connection()
                            alert_conn.execute("""
                                INSERT INTO alerts (
                                    alert_type, detection_type, severity, title, description,
                                    source_ip, destination_ip, source_port, destination_port,
                                    protocol, packet_count, threshold, details, evidence,
                                    mitre_technique, mitre_technique_id, mitre_technique_name, mitre_tactic,
                                    timestamp, session_id, resolved
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                            """, (
                                tmpl[1], 'RULE_BASED', tmpl[2], tmpl[0], f"Suspicious traffic pattern matched rule: {tmpl[0]}",
                                tmpl[5], tmpl[6], random.randint(1024, 65535), 443,
                                'TCP', random.randint(50, 250), 20, f"Simulated detection event on {tmpl[5]}",
                                f"Packet signature detected for {tmpl[3]}",
                                tmpl[3], tmpl[3], tmpl[4], tmpl[4],
                                int(time.time()), self.session_id
                            ))
                            alert_conn.commit()
                            sim_alert_count += 1
                            last_alert_time = time.time()
                        except Exception as alert_err:
                            logger.debug("Sim alert insert error: %s", alert_err)

                    time.sleep(0.20)
                except Exception as e:
                    logger.error("Simulation loop error: %s", e)
                    time.sleep(0.5)

            logger.info("*** SIMULATION STOPPED (Total Packets: %d) ***", self.packet_count)

        self.sniffer_thread = threading.Thread(target=simulation_loop, daemon=True)
        self.sniffer_thread.start()
        return True, "Simulation started successfully", self.session_id

    def start_capture(self, count=0, timeout=None, interface=None, simulate=False):
        """Start packet capture on specified or default interface.

        Returns (success: bool, message: str, session_id: int | None).
        """
        self.last_error = None

        if simulate or (interface and str(interface).lower() in ('simulate', 'simulation', 'demo')):
            return self.start_simulation()

        if self.running:
            logger.warning("Capture already running.")
            return False, "Capture is already running", self.session_id

        supported, reason = self.can_capture()
        if not supported:
            self.last_error = reason
            logger.error("Capture unsupported: %s", reason)
            return False, reason, None

        if interface:
            self.set_interface(interface)

        if not self.interface:
            logger.info("No capture interface found or selected.")
            return False, "No network capture interface available. Use the Remote Capture Agent to stream traffic.", None

        try:
            available = [self._normalize_interface(i) for i in get_if_list()]
        except Exception as e:
            logger.error("Could not list interfaces: %s", e)
            available = []

        is_device_name = self.interface.lower().startswith(
            r"\device\npf_"
        ) or self.interface.startswith("{")
        if is_device_name and self.interface not in available:
            logger.info("Interface %s not in available list.", self.interface)
            return False, f"Interface {self.interface} is not available.", None

        self.session_id = self.db.create_session()
        if not self.session_id:
            self.last_error = "Failed to create database capture session."
            logger.error(self.last_error)
            return False, self.last_error, None

        logger.info("Starting capture session: %s on interface: %s", self.session_id, self.interface)
        self.running = True
        self.packet_count = 0
        self.start_time = time.time()
        self._stop_event.clear()

        sniff_count = count if count and count > 0 else 0
        startup_event = threading.Event()
        startup_error = []

        def sniff_loop():
            logger.info("*** STARTING CAPTURE ON %s ***", self.interface)
            first_cycle = True
            while self.running and not self._stop_event.is_set():
                try:
                    if first_cycle:
                        startup_event.set()
                        first_cycle = False

                    sniff(
                        iface=self.interface,
                        prn=self._packet_callback,
                        store=False,
                        count=sniff_count,
                        timeout=2.0,
                        stop_filter=lambda p: self._stop_event.is_set()
                    )
                    if sniff_count or self._stop_event.is_set():
                        self.running = False
                        break
                except Exception as e:
                    logger.error("Sniff error on %s: %s", self.interface, e)
                    self.last_error = str(e)
                    if first_cycle:
                        startup_error.append(str(e))
                        startup_event.set()
                    self.running = False
                    break

            # Only end session here if stopped naturally (e.g. packet count reached)
            if self.session_id and not self._stop_event.is_set():
                self.db._flush_packet_queue()
                try:
                    self.tcp_tracker.close_inactive_sessions(300)
                except Exception:
                    pass
                self.db.end_session(self.session_id)
                self.session_id = None
            self.running = False
            logger.info("Capture stopped.")

        self.sniffer_thread = threading.Thread(target=sniff_loop, daemon=True)
        self.sniffer_thread.start()

        # Wait up to 500ms to verify thread initialization
        startup_event.wait(timeout=0.6)

        if startup_error or not self.sniffer_thread.is_alive():
            err_msg = startup_error[0] if startup_error else "Capture thread failed to bind"
            logger.warning("Sniff failed: %s", err_msg)
            self.running = False
            try:
                self.db.end_session(self.session_id)
            except Exception:
                pass
            self.session_id = None
            self.last_error = err_msg
            return False, err_msg, None

        logger.info("Sniffer thread running successfully.")
        return True, "Capture started successfully", self.session_id

    def stop_capture(self):
        """Stop active packet capture.

        Returns (success: bool, message: str, session_id: int | None).
        """
        if not self.running:
            return False, "Capture is not running", None

        logger.info("Stop capture called")
        session_id = self.session_id
        self._stop_event.set()
        self.running = False

        # Wait for sniffer thread to terminate so no lingering packets arrive
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=3)

        # Flush any remaining queued packets
        self.db._flush_packet_queue()

        # Close inactive TCP sessions and finalize session in DB
        if self.session_id:
            try:
                self.tcp_tracker.close_inactive_sessions(300)
            except Exception:
                pass
            self.db.end_session(self.session_id)
            self.session_id = None

        self.start_time = None
        self.simulation_mode = False
        return True, "Capture stopped successfully", session_id

    def get_packet_count(self):
        return self.packet_count

    def get_session_id(self):
        return self.session_id

    def get_capture_duration(self):
        if self.start_time and self.running:
            return int(time.time() - self.start_time)
        return 0

    def set_interface(self, iface):
        """Set the capture interface."""
        if self.running:
            logger.warning("Cannot change interface while capturing")
            return False
        self.interface = self._normalize_interface(iface)
        logger.info("Interface set to: %s", self.interface)
        return True

    @staticmethod
    def get_interfaces():
        """Get all network interfaces with real system details.

        Returns a list of dicts with: name, description, ip, mac, type.
        """
        interfaces = []
        try:
            scapy_ifaces = get_if_list()
            # Get psutil network info for enrichment if available
            ps_addrs = psutil.net_if_addrs() if psutil else {}
            ps_stats = psutil.net_if_stats() if psutil else {}

            for iface_name in scapy_ifaces:
                # Skip loopback
                if 'loopback' in iface_name.lower():
                    continue

                info = {
                    'name': iface_name,
                    'description': '',
                    'ip': None,
                    'mac': None,
                    'type': 'Unknown',
                    'is_up': False,
                    'speed': 0
                }

                # Try to get Scapy interface details
                try:
                    from scapy.all import IFACES
                    for iface_obj in IFACES.values():
                        iname = getattr(iface_obj, 'name', '')
                        iguid = getattr(iface_obj, 'guid', '')
                        if iname == iface_name or iguid == iface_name:
                            info['description'] = getattr(iface_obj, 'description', '') or ''
                            info['ip'] = getattr(iface_obj, 'ip', None)
                            info['mac'] = getattr(iface_obj, 'mac', None)
                            # Detect type from description
                            desc_lower = info['description'].lower()
                            if 'wi-fi' in desc_lower or 'wireless' in desc_lower or 'wlan' in desc_lower:
                                info['type'] = 'Wi-Fi'
                            elif 'ethernet' in desc_lower or 'realtek' in desc_lower:
                                info['type'] = 'Ethernet'
                            elif 'virtual' in desc_lower or 'vmware' in desc_lower or 'vbox' in desc_lower:
                                info['type'] = 'Virtual'
                            elif 'bluetooth' in desc_lower:
                                info['type'] = 'Bluetooth'
                            break
                except Exception:
                    pass

                # Enrich with psutil data
                for ps_name, addrs in ps_addrs.items():
                    if ps_name in iface_name or iface_name in ps_name:
                        for addr in addrs:
                            if addr.family.name == 'AF_INET' and not info['ip']:
                                info['ip'] = addr.address
                            elif addr.family.name == 'AF_LINK' and not info['mac']:
                                info['mac'] = addr.address
                        break

                # Get link status from psutil
                for ps_name, stats in ps_stats.items():
                    if ps_name in iface_name or iface_name in ps_name:
                        info['is_up'] = stats.isup
                        info['speed'] = stats.speed
                        break

                interfaces.append(info)

        except Exception as e:
            logger.error("Get interfaces error: %s", e)

        return interfaces
