"""
Central system manager for QS-AI-IDS
Coordinates all components and provides unified interface
"""

import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from config.settings import Settings
from core.quantum_detector import QuantumThreatDetector
from utils.ai_detector import ClassicalThreatDetector
from core.real_time_monitor import RealTimeMonitor
from core.live_packet_monitor import LivePacketMonitor, RealTimeNetworkAnalyzer
from utils.network_monitor import NetworkMonitor
from core.website_capture import WebAnalyzer
from ai.model_manager import ModelManager
from crypto.quantum_crypto import QuantumCrypto
from utils.logger import SystemLogger
from utils.threat_intelligence import ThreatIntelligence

class SystemManager:
    """Central system manager"""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = SystemLogger()
        self.running = False
        self.components = {}
        self.stats = {
            'start_time': None,
            'packets_processed': 0,
            'threats_detected': 0,
            'websites_analyzed': 0,
            'quantum_analyses': 0,
            'bytes_processed': 0,
            'active_connections': 0
        }
        
        # Initialize components
        self._initialize_components()
        
        # Initialize real-time monitoring
        self.real_time_monitor = RealTimeMonitor(self)
    
    def _initialize_components(self):
        """Initialize all system components"""
        try:
            # Core detection engines
            self.components['quantum_detector'] = QuantumThreatDetector(
                num_qubits=self.settings.quantum.num_qubits,
                use_quantum=self.settings.quantum.enabled
            )
            
            self.components['classical_detector'] = ClassicalThreatDetector()
            
            # Real-time network analyzer
            self.components['real_time_analyzer'] = RealTimeNetworkAnalyzer(
                self.components['quantum_detector'],
                self.components['classical_detector']
            )
            
            # Add threat callback to real-time analyzer
            self.components['real_time_analyzer'].add_threat_callback(
                self._handle_real_time_threat
            )
            
            # Traditional monitoring components
            self.components['network_monitor'] = NetworkMonitor(
                interfaces=self.settings.network.interfaces,
                buffer_size=self.settings.network.packet_buffer_size
            )
            
            self.components['web_analyzer'] = WebAnalyzer(
                quantum_detector=self.components['quantum_detector'],
                classical_detector=self.components['classical_detector']
            )
            
            # AI/ML components
            self.components['model_manager'] = ModelManager(
                model_path=self.settings.ai.model_path,
                config=self.settings.ai
            )
            
            # Security components
            if self.settings.security.encryption_enabled:
                self.components['crypto'] = QuantumCrypto()
            
            # Threat intelligence
            self.components['threat_intel'] = ThreatIntelligence()
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Component initialization failed: {e}")
            raise
    
    def start(self):
        """Start the system with real-time monitoring"""
        if self.running:
            return
        
        self.logger.info("Starting QS-AI-IDS system with real-time monitoring...")
        self.stats['start_time'] = datetime.now()
        self.running = True
        
        # Start real-time monitor first
        self.real_time_monitor.start()
        
        # Start components that need background processing
        for name, component in self.components.items():
            if hasattr(component, 'start'):
                try:
                    component.start()
                    self.logger.info(f"Started {name}")
                except Exception as e:
                    self.logger.error(f"Failed to start {name}: {e}")
        
        self.logger.info("QS-AI-IDS system started successfully with real-time monitoring")
    
    def shutdown(self):
        """Shutdown the system gracefully"""
        if not self.running:
            return
        
        self.logger.info("Shutting down QS-AI-IDS system...")
        self.running = False
        
        # Stop real-time monitor first
        if self.real_time_monitor:
            self.real_time_monitor.stop()
        
        # Stop all components
        for name, component in self.components.items():
            if hasattr(component, 'stop'):
                try:
                    component.stop()
                    self.logger.info(f"Stopped {name}")
                except Exception as e:
                    self.logger.error(f"Error stopping {name}: {e}")
        
        self.logger.info("QS-AI-IDS system shutdown complete")
    
    def start_network_monitoring(self, interface: Optional[str] = None, 
                               target_domain: Optional[str] = None):
        """Start real-time network traffic monitoring"""
        try:
            # Start real-time network analyzer
            analyzer = self.components['real_time_analyzer']
            analyzer.start_analysis(
                interface=interface,
                filter_str=self.settings.network.capture_filter
            )
            
            self.logger.info(f"Started real-time network monitoring on interface: {interface or 'default'}")
            
        except Exception as e:
            self.logger.error(f"Failed to start network monitoring: {e}")
            raise
    
    def _handle_real_time_threat(self, threat_event: Dict[str, Any]):
        """Handle real-time threat detection"""
        # Update statistics
        self.stats['threats_detected'] += 1
        
        # Add to real-time monitor
        if self.real_time_monitor:
            self.real_time_monitor.add_threat_detection(threat_event)
        
        # Log the threat
        self.logger.security_event(
            event_type="REAL_TIME_THREAT",
            severity=threat_event.get('severity', 0.5),
            details=threat_event
        )
        
        # Automated response if enabled
        if self.settings.security.threat_response:
            self._automated_threat_response(threat_event)
    
    def _automated_threat_response(self, threat_data: Dict[str, Any]):
        """Automated threat response for real-time threats"""
        try:
            source_ip = threat_data.get('source_ip')
            severity = threat_data.get('severity', 0)
            
            # Auto-block high severity threats
            if severity > 0.8 and source_ip:
                self.logger.info(f"Auto-blocking high severity threat from {source_ip}")
                # In a real implementation, this would add firewall rules
                threat_data['blocked'] = True
            
            # Send alerts for medium+ severity threats
            if severity > 0.5:
                self.logger.warning(f"Medium+ severity threat detected: {threat_data.get('threat_type')}")
        
        except Exception as e:
            self.logger.error(f"Automated response error: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status with real-time data"""
        uptime = None
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        # Get real-time statistics
        real_time_stats = {}
        if self.real_time_monitor:
            real_time_stats = self.real_time_monitor.get_real_time_data()
        
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'components_status': {
                name: getattr(comp, 'is_running', True) 
                for name, comp in self.components.items()
            },
            'statistics': self.stats.copy(),
            'real_time_data': real_time_stats,
            'settings': self.settings.to_dict()
        }
    
    def start_website_analysis(self, urls: List[str], depth: int = 2, 
                             max_pages: int = 50):
        """Start website analysis with real-time updates"""
        analyzer = self.components['web_analyzer']
        
        def analysis_callback(result):
            self.stats['websites_analyzed'] += 1
            if result.get('threats_detected'):
                self.stats['threats_detected'] += len(result['threats_detected'])
                self._handle_website_threat(result)
            
            # Add to real-time monitor if available
            if self.real_time_monitor and result.get('threats_detected'):
                for threat in result['threats_detected']:
                    threat_event = {
                        'timestamp': datetime.now(),
                        'threat_type': threat.get('type', 'Unknown'),
                        'source_ip': '0.0.0.0',  # Website analysis doesn't have source IP
                        'destination_ip': '0.0.0.0',
                        'severity': threat.get('confidence', 0.5),
                        'confidence': threat.get('confidence', 0.5),
                        'payload': result.get('url', ''),
                        'quantum_analysis': threat.get('quantum_analysis', {}),
                        'blocked': False
                    }
                    self.real_time_monitor.add_threat_detection(threat_event)
        
        # Start analysis in background thread
        thread = threading.Thread(
            target=analyzer.analyze_websites,
            args=(urls, depth, max_pages, analysis_callback)
        )
        thread.daemon = True
        thread.start()
    
    def verify_website(self, url: str) -> Dict[str, Any]:
        """Verify a single website with real-time analysis"""
        analyzer = self.components['web_analyzer']
        result = analyzer.verify_website(url)
        
        # Add quantum analysis if enabled
        if self.settings.quantum.enabled:
            quantum_detector = self.components['quantum_detector']
            quantum_result = quantum_detector.analyze_url(url)
            
            if quantum_result.get('threat_detected'):
                result.setdefault('threats_detected', []).append({
                    'type': quantum_result.get('threat_type', 'Unknown'),
                    'description': f"Quantum-enhanced detection: {quantum_result.get('threat_type')}",
                    'confidence': quantum_result.get('confidence', 0.5),
                    'quantum_analysis': quantum_result
                })
        
        return result
    
    def _handle_website_threat(self, threat_data: Dict[str, Any]):
        """Handle website-based threats"""
        self.logger.security_event(
            event_type="WEBSITE_THREAT",
            severity=threat_data.get('risk_score', 0.5),
            details=threat_data
        )
    
    def print_status(self):
        """Print system status to console with real-time info"""
        status = self.get_system_status()
        
        print("\n" + "="*60)
        print("🛡️ QS-AI-IDS REAL-TIME SYSTEM STATUS")
        print("="*60)
        print(f"Status: {'🟢 LIVE' if status['running'] else '🔴 STOPPED'}")
        
        if status['uptime_seconds']:
            hours = int(status['uptime_seconds'] // 3600)
            minutes = int((status['uptime_seconds'] % 3600) // 60)
            print(f"Uptime: {hours}h {minutes}m")
        
        print(f"Packets Processed: {status['statistics']['packets_processed']:,}")
        print(f"Threats Detected: {status['statistics']['threats_detected']:,}")
        print(f"Websites Analyzed: {status['statistics']['websites_analyzed']:,}")
        print(f"Quantum Analyses: {status['statistics']['quantum_analyses']:,}")
        
        # Real-time data
        real_time_data = status.get('real_time_data', {})
        if real_time_data:
            counters = real_time_data.get('counters', {})
            print(f"🔴 LIVE - Active Connections: {counters.get('active_connections', 0)}")
            print(f"🔴 LIVE - Bytes Processed: {counters.get('bytes_processed', 0):,}")
        
        print("\nComponent Status:")
        for name, running in status['components_status'].items():
            status_icon = "🟢" if running else "🔴"
            print(f"  {status_icon} {name}")
        
        print("="*60)
    
    def export_threat_intelligence(self, filepath: str):
        """Export threat intelligence data"""
        threat_intel = self.components['threat_intel']
        data = threat_intel.export_data()
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        self.logger.info(f"Threat intelligence exported to {filepath}")
    
    def generate_report(self, report_type: str = "comprehensive") -> Dict[str, Any]:
        """Generate system report"""
        status = self.get_system_status()
        
        report = {
            'report_type': report_type,
            'generated_at': datetime.now().isoformat(),
            'system_status': status,
            'threat_summary': self.components['threat_intel'].get_summary(),
            'model_performance': self.components['model_manager'].get_performance_metrics()
        }
        
        return report
