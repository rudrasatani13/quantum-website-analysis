"""
Network monitoring and packet analysis utilities
Real-time network traffic analysis and threat detection
"""

import socket
import struct
import threading
import time
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
import json
import random

class NetworkMonitor:
    """Network traffic monitoring and analysis"""

    def __init__(self, interfaces: List[str] = None, buffer_size: int = 65536):
        self.logger = logging.getLogger(__name__)
        self.interfaces = interfaces or ['eth0', 'wlan0']
        self.buffer_size = buffer_size
        self.monitoring = False
        self.packet_count = 0
        self.threat_count = 0

        # Network statistics
        self.stats = {
            'packets_captured': 0,
            'bytes_processed': 0,
            'threats_detected': 0,
            'start_time': None,
            'protocols': {},
            'source_ips': {},
            'destination_ips': {},
            'ports': {}
        }

        # Threat detection patterns
        self.threat_patterns = {
            'port_scan': {
                'description': 'Port scanning activity detected',
                'indicators': ['multiple_ports', 'rapid_connections', 'syn_flood']
            },
            'ddos': {
                'description': 'DDoS attack pattern detected',
                'indicators': ['high_volume', 'single_source', 'connection_flood']
            },
            'brute_force': {
                'description': 'Brute force attack detected',
                'indicators': ['repeated_auth_failures', 'dictionary_attack']
            },
            'data_exfiltration': {
                'description': 'Potential data exfiltration detected',
                'indicators': ['large_outbound', 'unusual_protocols', 'encrypted_traffic']
            }
        }

        # Callbacks for threat detection
        self.threat_callbacks = []

        self.logger.info(f"Network monitor initialized for interfaces: {self.interfaces}")

    def add_threat_callback(self, callback: Callable):
        """Add callback function for threat notifications"""
        self.threat_callbacks.append(callback)

    def start_monitoring(self, duration: Optional[int] = None):
        """Start network monitoring"""
        if self.monitoring:
            self.logger.warning("Monitoring already active")
            return

        self.monitoring = True
        self.stats['start_time'] = datetime.now()

        self.logger.info("Starting network monitoring...")

        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_loop, args=(duration,))
        monitor_thread.daemon = True
        monitor_thread.start()

        return monitor_thread

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        self.logger.info("Network monitoring stopped")

    def _monitor_loop(self, duration: Optional[int]):
        """Main monitoring loop"""
        try:
            end_time = time.time() + duration if duration else None

            while self.monitoring:
                if end_time and time.time() > end_time:
                    break

                # Simulate packet capture (in real implementation, use raw sockets)
                packets = self._simulate_packet_capture()

                for packet in packets:
                    self._process_packet(packet)

                time.sleep(0.1)  # Small delay to prevent excessive CPU usage

        except Exception as e:
            self.logger.error(f"Monitoring loop error: {e}")
        finally:
            self.monitoring = False

    def _simulate_packet_capture(self) -> List[Dict[str, Any]]:
        """Simulate packet capture for demonstration"""
        packets = []

        # Generate random packets
        for _ in range(random.randint(1, 10)):
            packet = {
                'timestamp': datetime.now(),
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'destination_ip': f"10.0.0.{random.randint(1, 254)}",
                'source_port': random.randint(1024, 65535),
                'destination_port': random.choice([80, 443, 22, 21, 25, 53, 3389, 5432]),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'size': random.randint(64, 1500),
                'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH']),
                'payload': self._generate_random_payload()
            }
            packets.append(packet)

        # Occasionally add suspicious packets
        if random.random() < 0.1:  # 10% chance
            suspicious_packet = self._generate_suspicious_packet()
            packets.append(suspicious_packet)

        return packets

    def _generate_random_payload(self) -> str:
        """Generate random packet payload"""
        payloads = [
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
            "SSH-2.0-OpenSSH_7.4",
            "220 FTP Server ready",
            "EHLO mail.example.com",
            ""  # Empty payload
        ]
        return random.choice(payloads)

    def _generate_suspicious_packet(self) -> Dict[str, Any]:
        """Generate suspicious packet for testing"""
        suspicious_types = [
            {
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.50',
                'destination_port': random.randint(1, 1024),
                'protocol': 'TCP',
                'flags': 'SYN',
                'payload': '',
                'threat_type': 'port_scan'
            },
            {
                'source_ip': '203.0.113.10',
                'destination_ip': '192.168.1.1',
                'destination_port': 22,
                'protocol': 'TCP',
                'flags': 'PSH',
                'payload': 'admin:password123',
                'threat_type': 'brute_force'
            },
            {
                'source_ip': '198.51.100.5',
                'destination_ip': '192.168.1.50',
                'destination_port': 80,
                'protocol': 'TCP',
                'flags': 'PSH',
                'payload': "GET /admin/config.php?id=1' OR '1'='1 HTTP/1.1",
                'threat_type': 'sql_injection'
            }
        ]

        suspicious = random.choice(suspicious_types)

        return {
            'timestamp': datetime.now(),
            'source_ip': suspicious['source_ip'],
            'destination_ip': suspicious['destination_ip'],
            'source_port': random.randint(1024, 65535),
            'destination_port': suspicious['destination_port'],
            'protocol': suspicious['protocol'],
            'size': random.randint(100, 500),
            'flags': suspicious['flags'],
            'payload': suspicious['payload'],
            'suspicious': True,
            'threat_type': suspicious['threat_type']
        }

    def _process_packet(self, packet: Dict[str, Any]):
        """Process individual packet"""
        try:
            # Update statistics
            self.stats['packets_captured'] += 1
            self.stats['bytes_processed'] += packet.get('size', 0)

            # Update protocol statistics
            protocol = packet.get('protocol', 'Unknown')
            self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1

            # Update IP statistics
            src_ip = packet.get('source_ip', 'Unknown')
            dst_ip = packet.get('destination_ip', 'Unknown')
            self.stats['source_ips'][src_ip] = self.stats['source_ips'].get(src_ip, 0) + 1
            self.stats['destination_ips'][dst_ip] = self.stats['destination_ips'].get(dst_ip, 0) + 1

            # Update port statistics
            dst_port = packet.get('destination_port', 0)
            self.stats['ports'][dst_port] = self.stats['ports'].get(dst_port, 0) + 1

            # Analyze packet for threats
            threats = self._analyze_packet_threats(packet)

            if threats:
                self.stats['threats_detected'] += len(threats)
                self._notify_threat_callbacks(packet, threats)

        except Exception as e:
            self.logger.error(f"Packet processing error: {e}")

    def _analyze_packet_threats(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze packet for potential threats"""
        threats = []

        try:
            # Check if packet is marked as suspicious (for simulation)
            if packet.get('suspicious', False):
                threat_type = packet.get('threat_type', 'unknown')

                threats.append({
                    'type': threat_type,
                    'severity': self._get_threat_severity(threat_type),
                    'confidence': random.uniform(0.7, 0.95),
                    'source_ip': packet.get('source_ip'),
                    'destination_ip': packet.get('destination_ip'),
                    'destination_port': packet.get('destination_port'),
                    'description': self.threat_patterns.get(threat_type, {}).get('description', 'Unknown threat'),
                    'timestamp': packet.get('timestamp'),
                    'packet_info': {
                        'protocol': packet.get('protocol'),
                        'size': packet.get('size'),
                        'flags': packet.get('flags')
                    }
                })

            # Additional threat analysis
            payload = packet.get('payload', '')

            # Check for SQL injection in payload
            if self._check_sql_injection(payload):
                threats.append({
                    'type': 'sql_injection',
                    'severity': 'high',
                    'confidence': 0.8,
                    'source_ip': packet.get('source_ip'),
                    'description': 'SQL injection attempt detected in packet payload',
                    'timestamp': packet.get('timestamp')
                })

            # Check for XSS in payload
            if self._check_xss_attack(payload):
                threats.append({
                    'type': 'xss_attack',
                    'severity': 'medium',
                    'confidence': 0.7,
                    'source_ip': packet.get('source_ip'),
                    'description': 'XSS attack attempt detected in packet payload',
                    'timestamp': packet.get('timestamp')
                })

            # Check for port scanning patterns
            port_scan_threat = self._check_port_scanning(packet)
            if port_scan_threat:
                threats.append(port_scan_threat)

            # Check for DDoS patterns
            ddos_threat = self._check_ddos_pattern(packet)
            if ddos_threat:
                threats.append(ddos_threat)

        except Exception as e:
            self.logger.error(f"Threat analysis error: {e}")

        return threats

    def _check_sql_injection(self, payload: str) -> bool:
        """Check for SQL injection patterns"""
        sql_patterns = [
            r'union\s+select', r'drop\s+table', r'insert\s+into',
            r'delete\s+from', r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1'
        ]

        import re
        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    def _check_xss_attack(self, payload: str) -> bool:
        """Check for XSS attack patterns"""
        xss_patterns = [
            r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
            r'alert\s*\(', r'document\.cookie'
        ]

        import re
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        return False

    def _check_port_scanning(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for port scanning patterns"""
        # Simple heuristic: multiple connections to different ports from same source
        src_ip = packet.get('source_ip')

        # In a real implementation, this would track connection patterns over time
        if random.random() < 0.05:  # 5% chance for demonstration
            return {
                'type': 'port_scan',
                'severity': 'medium',
                'confidence': 0.75,
                'source_ip': src_ip,
                'description': f'Port scanning detected from {src_ip}',
                'timestamp': packet.get('timestamp')
            }
        return None

    def _check_ddos_pattern(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check for DDoS attack patterns"""
        # Simple heuristic: high volume from single source
        src_ip = packet.get('source_ip')

        # In a real implementation, this would track packet rates
        if random.random() < 0.02:  # 2% chance for demonstration
            return {
                'type': 'ddos',
                'severity': 'high',
                'confidence': 0.85,
                'source_ip': src_ip,
                'description': f'DDoS attack pattern detected from {src_ip}',
                'timestamp': packet.get('timestamp')
            }
        return None

    def _get_threat_severity(self, threat_type: str) -> str:
        """Get severity level for threat type"""
        severity_map = {
            'port_scan': 'medium',
            'ddos': 'high',
            'brute_force': 'high',
            'sql_injection': 'high',
            'xss_attack': 'medium',
            'data_exfiltration': 'critical'
        }
        return severity_map.get(threat_type, 'low')

    def _notify_threat_callbacks(self, packet: Dict[str, Any], threats: List[Dict[str, Any]]):
        """Notify registered callbacks about threats"""
        for callback in self.threat_callbacks:
            try:
                for threat in threats:
                    callback({
                        'packet': packet,
                        'threat': threat,
                        'timestamp': datetime.now()
                    })
            except Exception as e:
                self.logger.error(f"Threat callback error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        stats = self.stats.copy()

        if stats['start_time']:
            uptime = (datetime.now() - stats['start_time']).total_seconds()
            stats['uptime_seconds'] = uptime
            stats['packets_per_second'] = stats['packets_captured'] / max(uptime, 1)
            stats['bytes_per_second'] = stats['bytes_processed'] / max(uptime, 1)

        return stats

    def get_top_sources(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top source IPs by packet count"""
        sorted_sources = sorted(
            self.stats['source_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {'ip': ip, 'packet_count': count}
            for ip, count in sorted_sources[:limit]
        ]

    def get_top_destinations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top destination IPs by packet count"""
        sorted_destinations = sorted(
            self.stats['destination_ips'].items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [
            {'ip': ip, 'packet_count': count}
            for ip, count in sorted_destinations[:limit]
        ]

    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get protocol distribution"""
        return self.stats['protocols'].copy()

    def export_statistics(self, filepath: str):
        """Export statistics to JSON file"""
        try:
            stats = self.get_statistics()

            # Convert datetime objects to strings for JSON serialization
            if 'start_time' in stats:
                stats['start_time'] = stats['start_time'].isoformat()

            with open(filepath, 'w') as f:
                json.dump(stats, f, indent=2, default=str)

            self.logger.info(f"Statistics exported to {filepath}")

        except Exception as e:
            self.logger.error(f"Failed to export statistics: {e}")

    def reset_statistics(self):
        """Reset monitoring statistics"""
        self.stats = {
            'packets_captured': 0,
            'bytes_processed': 0,
            'threats_detected': 0,
            'start_time': datetime.now() if self.monitoring else None,
            'protocols': {},
            'source_ips': {},
            'destination_ips': {},
            'ports': {}
        }
        self.logger.info("Statistics reset")
