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
            logger.info("*** STARTING SOC TRAFFIC SIMULATION (Session %s) ***", self.session_id)
            import random
            internal_hosts = ['192.168.1.105', '192.168.1.110', '192.168.1.115', '10.0.0.45', '10.0.0.88']
            external_endpoints = [
                ('142.250.190.46', 443, 'TLS', 'google.com'),
                ('140.82.121.4', 443, 'TLS', 'github.com'),
                ('20.112.52.29', 443, 'TLS', 'microsoft.com'),
                ('104.244.42.1', 443, 'TLS', 'api.twitter.com'),
                ('93.184.216.34', 80, 'HTTP', 'example.com'),
                ('8.8.8.8', 53, 'DNS', 'dns.google'),
                ('1.1.1.1', 53, 'DNS', 'one.one.one.one'),
                ('185.220.101.5', 8080, 'HTTP', 'c2-beacon-command.xyz'),
                ('198.51.100.45', 22, 'TCP', 'malicious-scanner.net')
            ]
            dns_domains = [
                'google.com', 'github.com', 'api.github.com', 'microsoft.com',
                'cloudflare.com', 'c2-beacon-command.xyz', 'update.windows.com', 'cdn.jsdelivr.net'
            ]
            gateway_mac = '00:50:56:c0:00:01'

            while self.running and not self._stop_event.is_set():
                try:
                    now_ts = time.time()
                    batch_size = random.randint(2, 5)
                    for _ in range(batch_size):
                        endpoint = random.choice(external_endpoints)
                        src_ip = random.choice(internal_hosts)
                        dst_ip = endpoint[0]
                        dst_port = endpoint[1]
                        proto = endpoint[2]
                        src_port = random.randint(49152, 65535)

                        if proto == 'DNS' or random.random() < 0.2:
                            q_domain = random.choice(dns_domains)
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': src_ip,
                                'dst_ip': '8.8.8.8',
                                'src_mac': '00:1a:2b:3c:4d:5e',
                                'dst_mac': gateway_mac,
                                'src_port': src_port,
                                'dst_port': 53,
                                'protocol': 'DNS',
                                'length': random.randint(60, 95),
                                'ttl': 64,
                                'tcp_flags': None,
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1
                            self.db.insert_dns_log(
                                domain=q_domain,
                                src_ip=src_ip,
                                dst_ip='8.8.8.8',
                                query_type='A',
                                is_response=1,
                                answers=[{'name': q_domain, 'type': 'A', 'ttl': 300, 'rdata': dst_ip}],
                                rcode=0
                            )
                        elif proto == 'TLS':
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_mac': '00:1a:2b:3c:4d:5e',
                                'dst_mac': gateway_mac,
                                'src_port': src_port,
                                'dst_port': 443,
                                'protocol': 'TLS',
                                'length': random.randint(300, 1420),
                                'ttl': 64,
                                'tcp_flags': 'PSH, ACK',
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1
                            self.tcp_tracker.process_packet(pkt_data)
                        elif proto == 'HTTP':
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_mac': '00:1a:2b:3c:4d:5e',
                                'dst_mac': gateway_mac,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'protocol': 'HTTP',
                                'length': random.randint(250, 1150),
                                'ttl': 64,
                                'tcp_flags': 'PSH, ACK',
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1
                            self.tcp_tracker.process_packet(pkt_data)
                        else:
                            pkt_data = {
                                'session_id': self.session_id,
                                'timestamp': now_ts,
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'src_mac': '00:1a:2b:3c:4d:5e',
                                'dst_mac': gateway_mac,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'protocol': proto,
                                'length': random.randint(64, 850),
                                'ttl': 64,
                                'tcp_flags': 'ACK',
                                'raw_data': None
                            }
                            self.db.insert_packet(pkt_data)
                            with self._count_lock:
                                self.packet_count += 1
                            if proto == 'TCP':
                                self.tcp_tracker.process_packet(pkt_data)

                    time.sleep(random.uniform(0.3, 0.6))
                except Exception as e:
                    logger.error("Simulation loop error: %s", e)
                    time.sleep(1)

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
            self.interface = self._get_default_interface()

        if not self.interface:
            self.last_error = "No capture interface found or selected."
            logger.error(self.last_error)
            return False, self.last_error, None

        try:
            available = [self._normalize_interface(i) for i in get_if_list()]
        except Exception as e:
            logger.error("Could not list interfaces: %s", e)
            available = []

        is_device_name = self.interface.lower().startswith(
            r"\device\npf_"
        ) or self.interface.startswith("{")
        if is_device_name and self.interface not in available:
            self.last_error = f"Interface {self.interface} not found in available interfaces."
            logger.error(self.last_error)
            return False, self.last_error, None

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

        if startup_error:
            self.running = False
            self.last_error = f"Sniff startup failed: {startup_error[0]}"
            try:
                self.db.end_session(self.session_id)
            except Exception:
                pass
            self.session_id = None
            return False, self.last_error, None

        if not self.sniffer_thread.is_alive():
            self.running = False
            self.last_error = "Capture thread terminated immediately upon start. Check interface permissions."
            try:
                self.db.end_session(self.session_id)
            except Exception:
                pass
            self.session_id = None
            return False, self.last_error, None

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
