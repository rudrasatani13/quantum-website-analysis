"""
Live packet monitoring with real-time processing
"""

import threading
import time
import queue
from scapy.all import sniff, AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
import logging
from typing import Callable, Optional, Dict, Any
from datetime import datetime
import psutil
import socket

class LivePacketMonitor:
    """Real-time packet monitoring and analysis"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or self._get_default_interface()
        self.running = False
        self.sniffer = None
        self.packet_queue = queue.Queue(maxsize=10000)
        self.packet_handlers = []
        self.statistics = {
            'packets_captured': 0,
            'packets_processed': 0,
            'bytes_captured': 0,
            'start_time': None,
            'last_packet_time': None
        }
        self.logger = logging.getLogger(__name__)
    
    def _get_default_interface(self) -> str:
        """Get default network interface"""
        try:
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            
            # Prefer ethernet interfaces
            for iface in interfaces:
                if 'eth' in iface.lower() or 'en' in iface.lower():
                    return iface
            
            # Fall back to any available interface
            return list(interfaces.keys())[0] if interfaces else 'any'
            
        except Exception:
            return 'any'
    
    def add_packet_handler(self, handler: Callable[[Any], None]):
        """Add packet handler function"""
        self.packet_handlers.append(handler)
    
    def remove_packet_handler(self, handler: Callable[[Any], None]):
        """Remove packet handler function"""
        if handler in self.packet_handlers:
            self.packet_handlers.remove(handler)
    
    def start_monitoring(self, filter_str: str = "tcp port 80 or tcp port 443"):
        """Start live packet monitoring"""
        if self.running:
            return
        
        self.running = True
        self.statistics['start_time'] = datetime.now()
        
        try:
            # Start packet sniffer
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                filter=filter_str,
                prn=self._packet_callback,
                store=False
            )
            
            self.sniffer.start()
            
            # Start packet processor thread
            processor_thread = threading.Thread(
                target=self._process_packets,
                daemon=True
            )
            processor_thread.start()
            
            self.logger.info(f"Started packet monitoring on interface {self.interface}")
            
        except Exception as e:
            self.logger.error(f"Failed to start packet monitoring: {e}")
            self.running = False
            raise
    
    def stop_monitoring(self):
        """Stop packet monitoring"""
        if not self.running:
            return
        
        self.running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        self.logger.info("Stopped packet monitoring")
    
    def _packet_callback(self, packet):
        """Callback for captured packets"""
        try:
            # Update statistics
            self.statistics['packets_captured'] += 1
            self.statistics['last_packet_time'] = datetime.now()
            
            if hasattr(packet, 'len'):
                self.statistics['bytes_captured'] += packet.len
            
            # Add to processing queue
            if not self.packet_queue.full():
                self.packet_queue.put(packet)
            
        except Exception as e:
            self.logger.error(f"Packet callback error: {e}")
    
    def _process_packets(self):
        """Process packets from queue"""
        while self.running:
            try:
                # Get packet from queue
                packet = self.packet_queue.get(timeout=1)
                
                # Process packet with all handlers
                for handler in self.packet_handlers:
                    try:
                        handler(packet)
                    except Exception as e:
                        self.logger.error(f"Packet handler error: {e}")
                
                self.statistics['packets_processed'] += 1
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Packet processing error: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        stats = self.statistics.copy()
        
        if stats['start_time']:
            runtime = (datetime.now() - stats['start_time']).total_seconds()
            stats['runtime_seconds'] = runtime
            stats['packets_per_second'] = stats['packets_captured'] / max(runtime, 1)
            stats['bytes_per_second'] = stats['bytes_captured'] / max(runtime, 1)
        
        return stats
    
    def get_interface_info(self) -> Dict[str, Any]:
        """Get network interface information"""
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            interface_info = {}
            
            for iface, addrs in interfaces.items():
                interface_info[iface] = {
                    'addresses': [addr.address for addr in addrs],
                    'is_up': stats.get(iface, {}).isup if iface in stats else False,
                    'speed': stats.get(iface, {}).speed if iface in stats else 0
                }
            
            return interface_info
            
        except Exception as e:
            self.logger.error(f"Error getting interface info: {e}")
            return {}

class RealTimeNetworkAnalyzer:
    """Real-time network traffic analyzer"""
    
    def __init__(self, quantum_detector, classical_detector):
        self.quantum_detector = quantum_detector
        self.classical_detector = classical_detector
        self.packet_monitor = LivePacketMonitor()
        self.threat_callbacks = []
        self.logger = logging.getLogger(__name__)
        
        # Add packet handler
        self.packet_monitor.add_packet_handler(self._analyze_packet)
    
    def add_threat_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add threat detection callback"""
        self.threat_callbacks.append(callback)
    
    def start_analysis(self, interface: Optional[str] = None, 
                      filter_str: str = "tcp port 80 or tcp port 443"):
        """Start real-time network analysis"""
        if interface:
            self.packet_monitor.interface = interface
        
        self.packet_monitor.start_monitoring(filter_str)
        self.logger.info("Started real-time network analysis")
    
    def stop_analysis(self):
        """Stop real-time network analysis"""
        self.packet_monitor.stop_monitoring()
        self.logger.info("Stopped real-time network analysis")
    
    def _analyze_packet(self, packet):
        """Analyze individual packet for threats"""
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            
            if not packet_info:
                return
            
            # Analyze with quantum detector
            quantum_result = self.quantum_detector.analyze_packet(packet)
            
            # Analyze with classical detector
            classical_result = self.classical_detector.analyze_packet(packet)
            
            # Combine results
            threat_detected = quantum_result.get('threat_detected', False) or \
                            classical_result.get('threat_detected', False)
            
            if threat_detected:
                # Create threat event
                threat_event = {
                    'timestamp': datetime.now(),
                    'packet_info': packet_info,
                    'quantum_result': quantum_result,
                    'classical_result': classical_result,
                    'threat_type': quantum_result.get('threat_type') or classical_result.get('threat_type'),
                    'severity': max(
                        quantum_result.get('confidence', 0),
                        classical_result.get('confidence', 0)
                    ),
                    'source_ip': packet_info.get('src_ip'),
                    'destination_ip': packet_info.get('dst_ip')
                }
                
                # Notify threat callbacks
                for callback in self.threat_callbacks:
                    try:
                        callback(threat_event)
                    except Exception as e:
                        self.logger.error(f"Threat callback error: {e}")
        
        except Exception as e:
            self.logger.error(f"Packet analysis error: {e}")
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant information from packet"""
        try:
            info = {}
            
            # IP layer information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info['src_ip'] = ip_layer.src
                info['dst_ip'] = ip_layer.dst
                info['protocol'] = ip_layer.proto
                info['packet_size'] = len(packet)
            
            # TCP layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                info['src_port'] = tcp_layer.sport
                info['dst_port'] = tcp_layer.dport
                info['flags'] = tcp_layer.flags
            
            # UDP layer information
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                info['src_port'] = udp_layer.sport
                info['dst_port'] = udp_layer.dport
            
            # HTTP layer information
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                info['http_method'] = http_layer.Method.decode() if hasattr(http_layer, 'Method') else 'GET'
                info['http_host'] = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ''
                info['http_path'] = http_layer.Path.decode() if hasattr(http_layer, 'Path') else '/'
            
            return info if info else None
            
        except Exception as e:
            self.logger.error(f"Packet info extraction error: {e}")
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics"""
        return self.packet_monitor.get_statistics()
