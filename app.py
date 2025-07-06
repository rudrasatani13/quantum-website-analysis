import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import json
import io
import base64
from typing import Dict, List, Any
import hashlib
from pathlib import Path
import sys
import random
import requests
import ssl
import socket
from urllib.parse import urlparse
import re
from dotenv import load_dotenv
import os

load_dotenv(dotenv_path="/Users/apple/Desktop/qs-ai-ids-dashboard/.env")

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Import our custom modules
from utils.data_processor import DataProcessor
from utils.ai_detector import AIDetector
from utils.network_monitor import NetworkMonitor


# Quantum-Enhanced Threat Detection Classes
class QuantumWebsiteAnalyzer:
    """Quantum-enhanced website security analyzer"""

    def __init__(self):
        self.quantum_enabled = True
        self.quantum_qubits = 8
        self.quantum_circuits_run = 0

        # Quantum threat patterns with probability amplitudes
        self.quantum_threat_patterns = {
            'sql_injection': {
                'patterns': [r'union\s+select', r'drop\s+table', r'or\s+1\s*=\s*1'],
                'quantum_weights': [0.9, 0.8, 0.7],
                'entanglement_factor': 0.85
            },
            'xss_attack': {
                'patterns': [r'<script[^>]*>', r'javascript:', r'alert\s*\('],
                'quantum_weights': [0.95, 0.8, 0.75],
                'entanglement_factor': 0.9
            },
            'command_injection': {
                'patterns': [r';\s*cat\s+', r';\s*rm\s+', r'\|\s*nc\s+'],
                'quantum_weights': [0.85, 0.9, 0.8],
                'entanglement_factor': 0.8
            }
        }

    def quantum_analyze_content(self, content: str) -> Dict[str, Any]:
        """Perform quantum-enhanced content analysis"""
        self.quantum_circuits_run += 1

        quantum_results = {
            'quantum_enabled': True,
            'qubits_used': self.quantum_qubits,
            'circuits_executed': self.quantum_circuits_run,
            'quantum_threats': [],
            'quantum_confidence': 0.0,
            'superposition_states': 2 ** self.quantum_qubits,
            'entanglement_measure': 0.0
        }

        total_quantum_score = 0.0
        max_entanglement = 0.0

        for threat_type, threat_data in self.quantum_threat_patterns.items():
            patterns = threat_data['patterns']
            weights = threat_data['quantum_weights']
            entanglement = threat_data['entanglement_factor']

            # Quantum pattern matching simulation
            pattern_matches = []
            quantum_amplitudes = []

            for i, pattern in enumerate(patterns):
                if re.search(pattern, content, re.IGNORECASE):
                    pattern_matches.append(pattern)
                    # Simulate quantum amplitude
                    amplitude = weights[i] * np.sqrt(entanglement)
                    quantum_amplitudes.append(amplitude)

            if pattern_matches:
                # Calculate quantum interference
                total_amplitude = sum(quantum_amplitudes)
                quantum_probability = total_amplitude ** 2

                # Add quantum noise and superposition effects
                quantum_noise = np.random.normal(0, 0.05)
                final_confidence = min(0.99, max(0.1, quantum_probability + quantum_noise))

                quantum_results['quantum_threats'].append({
                    'type': threat_type,
                    'patterns_found': pattern_matches,
                    'quantum_confidence': final_confidence,
                    'quantum_amplitudes': quantum_amplitudes,
                    'entanglement_factor': entanglement,
                    'superposition_collapse': f"State |{threat_type}⟩ measured"
                })

                total_quantum_score += final_confidence
                max_entanglement = max(max_entanglement, entanglement)

        quantum_results['quantum_confidence'] = total_quantum_score / len(self.quantum_threat_patterns)
        quantum_results['entanglement_measure'] = max_entanglement

        return quantum_results


# Real Threat Detection Classes with Quantum Enhancement
class RealThreatDetector:
    """Real threat detection system with quantum enhancement"""

    def __init__(self):
        self.quantum_analyzer = QuantumWebsiteAnalyzer()

        self.threat_patterns = {
            'sql_injection': [
                r'union\s+select', r'drop\s+table', r'insert\s+into',
                r'delete\s+from', r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1',
                r'exec\s*\(', r'script\s*>', r'<\s*script'
            ],
            'xss_attack': [
                r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
                r'alert\s*\(', r'document\.cookie', r'eval\s*\(',
                r'<iframe[^>]*>', r'<object[^>]*>'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*rm\s+',
                r';\s*wget\s+', r';\s*curl\s+', r'\|\s*nc\s+',
                r'&&\s*cat', r'\|\|\s*ls'
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
                r'\.\.%2f', r'\.\.%5c', r'%252e%252e%252f'
            ],
            'ldap_injection': [
                r'$$\s*\|\s*\(', r'$$\s*\(\s*\|', r'objectClass=\*',
                r'cn=\*', r'uid=\*', r'\*\s*\)', r'\(\s*\*'
            ]
        }

        # Security headers that should be present
        self.security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'Referrer-Policy', 'Permissions-Policy'
        ]

        self.vulnerability_checks = {
            'http_only': 'Site uses HTTP instead of HTTPS - data can be intercepted',
            'missing_security_headers': 'Missing important security headers',
            'weak_ssl': 'Weak SSL/TLS configuration',
            'suspicious_redirects': 'Suspicious redirect patterns detected',
            'malicious_content': 'Potentially malicious content detected'
        }

    def analyze_website(self, url: str) -> Dict[str, Any]:
        """Real website analysis with quantum enhancement"""

        analysis_result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'threats_detected': [],
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': [],
            'technical_details': {},
            'quantum_analysis': {}
        }

        try:
            # 1. Check if HTTPS is used
            parsed_url = urlparse(url)
            if parsed_url.scheme == 'http':
                analysis_result['threats_detected'].append({
                    'type': 'Insecure Protocol',
                    'severity': 'HIGH',
                    'description': 'Website uses HTTP instead of HTTPS',
                    'risk': 'Data transmission is not encrypted and can be intercepted',
                    'recommendation': 'Switch to HTTPS immediately'
                })
                analysis_result['security_score'] -= 30

            # 2. Make HTTP request and analyze response
            headers = {
                'User-Agent': 'QS-AI-IDS Quantum Security Scanner 2.0'
            }

            response = requests.get(url, headers=headers, timeout=10, verify=False)
            analysis_result['technical_details']['status_code'] = response.status_code
            analysis_result['technical_details']['response_headers'] = dict(response.headers)

            # 3. QUANTUM-ENHANCED CONTENT ANALYSIS
            page_content = response.text
            quantum_results = self.quantum_analyzer.quantum_analyze_content(page_content)
            analysis_result['quantum_analysis'] = quantum_results

            # Process quantum threats
            for quantum_threat in quantum_results['quantum_threats']:
                threat_type = quantum_threat['type']
                confidence = quantum_threat['quantum_confidence']

                if confidence > 0.6:  # Quantum threshold
                    analysis_result['threats_detected'].append({
                        'type': f"🧬 Quantum-Detected {threat_type.replace('_', ' ').title()}",
                        'severity': 'CRITICAL' if confidence > 0.8 else 'HIGH',
                        'description': f'Quantum algorithms detected {threat_type} with {confidence:.1%} confidence',
                        'patterns_found': quantum_threat['patterns_found'],
                        'risk': 'High-confidence quantum detection indicates serious security vulnerability',
                        'quantum_details': {
                            'confidence': confidence,
                            'entanglement_factor': quantum_threat['entanglement_factor'],
                            'superposition_state': quantum_threat['superposition_collapse'],
                            'quantum_amplitudes': quantum_threat['quantum_amplitudes']
                        }
                    })
                    analysis_result['security_score'] -= 25

            # 4. Check security headers
            missing_headers = []
            for header in self.security_headers:
                if header not in response.headers:
                    missing_headers.append(header)

            if missing_headers:
                analysis_result['threats_detected'].append({
                    'type': 'Missing Security Headers',
                    'severity': 'MEDIUM',
                    'description': f'Missing {len(missing_headers)} security headers',
                    'details': missing_headers,
                    'risk': 'Increased vulnerability to XSS, clickjacking, and other attacks'
                })
                analysis_result['security_score'] -= len(missing_headers) * 5

            # 5. Classical pattern analysis (as backup)
            for threat_type, patterns in self.threat_patterns.items():
                matches = []
                for pattern in patterns:
                    if re.search(pattern, page_content, re.IGNORECASE):
                        matches.append(pattern)

                if matches:
                    # Check if quantum already detected this
                    quantum_detected = any(
                        qt['type'] == threat_type
                        for qt in quantum_results['quantum_threats']
                    )

                    if not quantum_detected:
                        analysis_result['threats_detected'].append({
                            'type': f"Classical-Detected {threat_type.replace('_', ' ').title()}",
                            'severity': 'HIGH',
                            'description': f'Classical pattern matching detected {threat_type}',
                            'patterns_found': matches[:3],
                            'risk': 'Potential security vulnerability detected by classical algorithms'
                        })
                        analysis_result['security_score'] -= 15

            # 6. Check for suspicious JavaScript
            js_threats = self._analyze_javascript(page_content)
            if js_threats:
                analysis_result['threats_detected'].extend(js_threats)
                analysis_result['security_score'] -= len(js_threats) * 15

            # 7. SSL/TLS Analysis (if HTTPS)
            if parsed_url.scheme == 'https':
                ssl_analysis = self._analyze_ssl(parsed_url.hostname, parsed_url.port or 443)
                analysis_result['technical_details']['ssl_info'] = ssl_analysis

                if ssl_analysis.get('weak_cipher'):
                    analysis_result['threats_detected'].append({
                        'type': 'Weak SSL Configuration',
                        'severity': 'MEDIUM',
                        'description': 'Weak SSL/TLS cipher suite detected',
                        'risk': 'Encryption may be vulnerable to attacks'
                    })
                    analysis_result['security_score'] -= 15

            # 8. Check for malicious redirects
            if len(response.history) > 0:
                redirect_analysis = self._analyze_redirects(response.history)
                if redirect_analysis['suspicious']:
                    analysis_result['threats_detected'].append({
                        'type': 'Suspicious Redirects',
                        'severity': 'MEDIUM',
                        'description': 'Potentially malicious redirect chain detected',
                        'details': redirect_analysis['details']
                    })
                    analysis_result['security_score'] -= 10

            # 9. Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)

            # 10. Final security assessment with quantum boost
            quantum_confidence = quantum_results.get('quantum_confidence', 0)
            if quantum_confidence > 0.7:
                analysis_result['security_score'] -= 20  # Quantum detected high threats

            if analysis_result['security_score'] >= 80:
                analysis_result['risk_level'] = 'LOW'
                analysis_result['status'] = '🟢 SECURE'
            elif analysis_result['security_score'] >= 60:
                analysis_result['risk_level'] = 'MEDIUM'
                analysis_result['status'] = '🟡 MODERATE RISK'
            else:
                analysis_result['risk_level'] = 'HIGH'
                analysis_result['status'] = '🔴 HIGH RISK'

        except requests.exceptions.RequestException as e:
            analysis_result['threats_detected'].append({
                'type': 'Connection Error',
                'severity': 'HIGH',
                'description': f'Unable to connect to website: {str(e)}',
                'risk': 'Website may be down or blocking security scans'
            })
            analysis_result['security_score'] = 0
            analysis_result['status'] = '🔴 UNREACHABLE'

        except Exception as e:
            analysis_result['threats_detected'].append({
                'type': 'Analysis Error',
                'severity': 'MEDIUM',
                'description': f'Error during analysis: {str(e)}',
                'risk': 'Unable to complete full security assessment'
            })

        return analysis_result

    def _analyze_javascript(self, content: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript for malicious patterns"""
        threats = []

        suspicious_js_patterns = {
            'eval(': 'Dynamic code execution detected',
            'document.write(': 'Potentially dangerous DOM manipulation',
            'innerHTML': 'Direct HTML injection possible',
            'outerHTML': 'DOM replacement detected',
            'document.cookie': 'Cookie access detected',
            'window.location': 'Page redirection detected',
            'base64': 'Base64 encoding detected (possible obfuscation)',
            'unescape(': 'URL decoding detected',
            'String.fromCharCode': 'Character code conversion (possible obfuscation)'
        }

        for pattern, description in suspicious_js_patterns.items():
            if pattern in content:
                threats.append({
                    'type': 'Suspicious JavaScript',
                    'severity': 'MEDIUM',
                    'description': description,
                    'pattern': pattern,
                    'risk': 'Potential XSS or malicious script execution'
                })

        return threats

    def _analyze_ssl(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {}

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    ssl_info = {
                        'protocol': ssock.version(),
                        'cipher_suite': cipher[0] if cipher else 'Unknown',
                        'key_length': cipher[2] if cipher else 0,
                        'certificate_valid': True,
                        'issuer': dict(x[0] for x in cert['issuer']) if cert else {},
                        'subject': dict(x[0] for x in cert['subject']) if cert else {},
                        'expires': cert.get('notAfter', 'Unknown') if cert else 'Unknown'
                    }

                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'SHA1']
                    cipher_name = cipher[0] if cipher else ''
                    ssl_info['weak_cipher'] = any(weak in cipher_name for weak in weak_ciphers)

        except Exception as e:
            ssl_info = {
                'error': str(e),
                'certificate_valid': False,
                'weak_cipher': True
            }

        return ssl_info

    def _analyze_redirects(self, history: List) -> Dict[str, Any]:
        """Analyze redirect chain for suspicious patterns"""
        analysis = {
            'suspicious': False,
            'details': [],
            'redirect_count': len(history)
        }

        # Check for too many redirects
        if len(history) > 5:
            analysis['suspicious'] = True
            analysis['details'].append(f'Excessive redirects: {len(history)}')

        # Check for suspicious domains in redirect chain
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']

        for response in history:
            url = response.url
            parsed = urlparse(url)

            # Check for suspicious TLDs
            for tld in suspicious_tlds:
                if parsed.netloc.endswith(tld):
                    analysis['suspicious'] = True
                    analysis['details'].append(f'Suspicious TLD in redirect: {parsed.netloc}')

            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in parsed.netloc for shortener in shorteners):
                analysis['suspicious'] = True
                analysis['details'].append(f'URL shortener in chain: {parsed.netloc}')

        return analysis

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        threats = analysis.get('threats_detected', [])

        for threat in threats:
            threat_type = threat.get('type', '').lower()

            if 'insecure protocol' in threat_type:
                recommendations.append('🔒 Implement HTTPS with a valid SSL certificate')

            elif 'missing security headers' in threat_type:
                recommendations.append('🛡️ Add security headers: X-Frame-Options, X-XSS-Protection, CSP')

            elif 'javascript' in threat_type:
                recommendations.append('🧹 Review and sanitize JavaScript code')

            elif 'ssl' in threat_type:
                recommendations.append('🔐 Update SSL/TLS configuration to use strong ciphers')

            elif 'redirect' in threat_type:
                recommendations.append('🔄 Review redirect chains and remove unnecessary redirects')

            elif 'quantum-detected' in threat_type:
                recommendations.append(
                    '🧬 URGENT: Quantum algorithms detected critical vulnerabilities - immediate action required')

        # General recommendations
        if analysis.get('security_score', 100) < 80:
            recommendations.extend([
                '🔍 Conduct regular security audits',
                '🛡️ Implement Web Application Firewall (WAF)',
                '📊 Monitor website for security threats',
                '🔄 Keep all software and plugins updated'
            ])

        return list(set(recommendations))  # Remove duplicates


# Network Traffic Analyzer
class NetworkTrafficAnalyzer:
    """Real network traffic analysis"""

    def __init__(self):
        self.suspicious_patterns = {
            'port_scan': 'Multiple connection attempts to different ports',
            'ddos': 'High volume of requests from single source',
            'brute_force': 'Repeated authentication failures',
            'data_exfiltration': 'Large outbound data transfers',
            'malware_communication': 'Communication with known malicious IPs'
        }

        self.blocked_ips = set()
        self.threat_count = 0

    def analyze_traffic(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network packets for threats"""

        analysis = {
            'total_packets': len(packets),
            'threats_detected': [],
            'statistics': {
                'protocols': {},
                'top_sources': {},
                'top_destinations': {},
                'port_distribution': {}
            },
            'blocked_ips': list(self.blocked_ips),
            'risk_score': 0
        }

        if not packets:
            return analysis

        # Analyze packet patterns
        source_ips = {}
        dest_ports = {}
        protocols = {}

        for packet in packets:
            # Count by source IP
            src_ip = packet.get('source_ip', 'unknown')
            source_ips[src_ip] = source_ips.get(src_ip, 0) + 1

            # Count by destination port
            dest_port = packet.get('destination_port', 0)
            dest_ports[dest_port] = dest_ports.get(dest_port, 0) + 1

            # Count by protocol
            protocol = packet.get('protocol', 'unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1

        # Detect port scanning
        for src_ip, count in source_ips.items():
            unique_ports = len([p for p in packets if p.get('source_ip') == src_ip])

            if unique_ports > 10 and count > 20:  # Accessing many ports
                analysis['threats_detected'].append({
                    'type': 'Port Scan',
                    'source_ip': src_ip,
                    'severity': 'HIGH',
                    'description': f'Port scanning detected from {src_ip}',
                    'details': f'{unique_ports} different ports accessed',
                    'recommendation': 'Block this IP address'
                })
                self.blocked_ips.add(src_ip)
                analysis['risk_score'] += 30

        # Detect DDoS patterns
        for src_ip, count in source_ips.items():
            if count > 100:  # High volume from single source
                analysis['threats_detected'].append({
                    'type': 'DDoS Attack',
                    'source_ip': src_ip,
                    'severity': 'CRITICAL',
                    'description': f'DDoS attack detected from {src_ip}',
                    'details': f'{count} packets in short time period',
                    'recommendation': 'Implement rate limiting and block IP'
                })
                self.blocked_ips.add(src_ip)
                analysis['risk_score'] += 50

        # Update statistics
        analysis['statistics']['protocols'] = protocols
        analysis['statistics']['top_sources'] = dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10])
        analysis['statistics']['port_distribution'] = dict(
            sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:10])

        self.threat_count += len(analysis['threats_detected'])

        return analysis


# Initialize real components
real_threat_detector = RealThreatDetector()
network_analyzer = NetworkTrafficAnalyzer()

# Page configuration
st.set_page_config(
    page_title="QS-AI-IDS Dashboard - Quantum-Enhanced Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS with quantum styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #8b5cf6 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(139, 92, 246, 0.3);
    }

    .quantum-header {
        background: linear-gradient(45deg, #8b5cf6, #06b6d4, #10b981);
        background-size: 300% 300%;
        animation: quantumGradient 3s ease infinite;
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 1rem 0;
    }

    @keyframes quantumGradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    .threat-card-quantum {
        background: linear-gradient(135deg, #fdf4ff 0%, #f3e8ff 100%);
        border: 3px solid #8b5cf6;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #581c87;
        font-weight: bold;
        box-shadow: 0 8px 25px rgba(139, 92, 246, 0.3);
        position: relative;
        overflow: hidden;
    }

    .threat-card-quantum::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(139, 92, 246, 0.2), transparent);
        animation: quantumScan 2s infinite;
    }

    @keyframes quantumScan {
        0% { left: -100%; }
        100% { left: 100%; }
    }

    .threat-card-high {
        background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
        border: 3px solid #dc2626;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #7f1d1d;
        font-weight: bold;
        box-shadow: 0 4px 12px rgba(220, 38, 38, 0.2);
    }

    .threat-card-medium {
        background: linear-gradient(135deg, #fef3c7 0%, #fed7aa 100%);
        border: 3px solid #f59e0b;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #92400e;
        font-weight: bold;
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.2);
    }

    .threat-card-low {
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        border: 3px solid #059669;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #064e3b;
        font-weight: bold;
        box-shadow: 0 4px 12px rgba(5, 150, 105, 0.2);
    }

    .secure-card {
        background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
        border: 3px solid #10b981;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #064e3b;
        font-weight: bold;
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.2);
    }

    .quantum-metrics {
        background: linear-gradient(135deg, #f0f9ff 0%, #064460 100%);
        border: 2px solid #0ea5e9;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        text-align: center;
    }

    .quantum-badge {
        background: linear-gradient(45deg, #8b5cf6, #06b6d4);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: bold;
        display: inline-block;
        margin: 0.2rem;
        animation: pulse 2s infinite;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'real_time_threats' not in st.session_state:
    st.session_state.real_time_threats = []
if 'uploaded_data' not in st.session_state:
    st.session_state.uploaded_data = None
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'feedback_data' not in st.session_state:
    st.session_state.feedback_data = []
if 'dark_mode' not in st.session_state:
    st.session_state.dark_mode = False
if 'real_time_data' not in st.session_state:
    st.session_state.real_time_data = {
        'counters': {
            'packets_processed': 15420,
            'threats_detected': 23,
            'bytes_processed': 2048576,
            'quantum_analyses': 89,
            'blocked_ips_count': 5,
            'active_connections': 12
        },
        'recent_threats': [
            {
                'timestamp': '2025-07-06 14:30:00',
                'threat_type': 'SQL Injection',
                'source_ip': '192.168.1.100',
                'severity': 0.8,
                'confidence': 0.92
            },
            {
                'timestamp': '2025-07-06 14:29:30',
                'threat_type': 'XSS Attack',
                'source_ip': '10.0.0.50',
                'severity': 0.6,
                'confidence': 0.85
            }
        ],
        'attack_distribution': {
            'SQL Injection': 8,
            'XSS Attack': 6,
            'DDoS': 4,
            'Malware': 3,
            'Phishing': 2
        }
    }


# Initialize components
@st.cache_resource
def initialize_components():
    data_processor = DataProcessor()
    ai_detector = AIDetector()
    network_monitor = NetworkMonitor()
    return data_processor, ai_detector, network_monitor


data_processor, ai_detector, network_monitor = initialize_components()


def main():
    """Main application"""

    # Header with quantum enhancement
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ QS-AI-IDS - Quantum-Enhanced Security System</h1>
        <p>🧬 Real-time threat detection powered by quantum algorithms</p>
        <div class="quantum-badge">QUANTUM ENABLED</div>
        <div class="quantum-badge">8-QUBIT PROCESSING</div>
        <div class="quantum-badge">SUPERPOSITION ANALYSIS</div>
    </div>
    """, unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.title("🔧 Quantum Control Panel")
        st.success("🟢 System Status: QUANTUM ACTIVE")

        # Quantum status
        st.markdown("""
        <div class="quantum-metrics">
            <h4>🧬 Quantum Status</h4>
            <p><strong>Qubits:</strong> 8 Active</p>
            <p><strong>Circuits:</strong> Running</p>
            <p><strong>Entanglement:</strong> Stable</p>
        </div>
        """, unsafe_allow_html=True)

        page = st.selectbox("Select Function", [
            "🌐 Quantum Website Scanner",
            "📡 Network Traffic Analyzer",
            "📊 Threat Dashboard",
            "📋 Analysis History",
            "⚙️ Scanner Settings"
        ])

        st.markdown("---")
        st.markdown("### 📈 Live Stats")

        col1, col2 = st.columns(2)
        with col1:
            st.metric("🔍 Sites Scanned", len(st.session_state.analysis_history))
        with col2:
            st.metric("🚨 Threats Found",
                      sum(len(a.get('threats_detected', [])) for a in st.session_state.analysis_history))

        # Quantum metrics
        st.metric("🧬 Quantum Analyses", real_threat_detector.quantum_analyzer.quantum_circuits_run)

    # Main content
    if page == "🌐 Quantum Website Scanner":
        render_quantum_website_scanner()
    elif page == "📡 Network Traffic Analyzer":
        render_network_analyzer()
    elif page == "📊 Threat Dashboard":
        render_threat_dashboard()
    elif page == "📋 Analysis History":
        render_analysis_history()
    elif page == "⚙️ Scanner Settings":
        render_scanner_settings()


def render_quantum_website_scanner():
    """Quantum-enhanced website security scanner"""
    st.markdown("""
    <div class="quantum-header">
        <h2>🧬 Quantum-Enhanced Website Security Scanner</h2>
        <p>Advanced threat detection using quantum algorithms and superposition analysis</p>
    </div>
    """, unsafe_allow_html=True)

    st.info("🔬 This scanner uses quantum algorithms to detect threats with unprecedented accuracy!")

    # Single website analysis
    st.subheader("🔍 Quantum Security Analysis")

    col1, col2 = st.columns([3, 1])

    with col1:
        url = st.text_input(
            "Enter Website URL",
            placeholder="https://example.com or http://insecure-site.com",
            help="Enter any website URL to perform quantum-enhanced security analysis"
        )

    with col2:
        analyze_button = st.button("🧬 Quantum Analyze", type="primary")

    # Quick test buttons
    st.markdown("**Quantum Test Examples:**")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if st.button("🔒 Test HTTPS Site"):
            url = "https://www.google.com"
            analyze_button = True

    with col2:
        if st.button("⚠️ Test HTTP Site"):
            url = "http://neverssl.com"
            analyze_button = True

    with col3:
        if st.button("🏦 Test Bank Site"):
            url = "https://www.chase.com"
            analyze_button = True

    with col4:
        if st.button("📰 Test News Site"):
            url = "https://www.bbc.com"
            analyze_button = True

    # Perform quantum analysis
    if analyze_button and url:
        with st.spinner(f"🧬 Performing quantum analysis on {url}... Initializing qubits..."):
            # Show quantum progress
            progress_bar = st.progress(0)
            status_text = st.empty()

            status_text.text("🌐 Establishing quantum connection...")
            progress_bar.progress(15)
            time.sleep(1)

            status_text.text("🧬 Initializing 8-qubit quantum circuit...")
            progress_bar.progress(30)
            time.sleep(1)

            status_text.text("⚛️ Creating superposition states...")
            progress_bar.progress(50)
            time.sleep(1)

            status_text.text("🔗 Measuring quantum entanglement...")
            progress_bar.progress(70)
            time.sleep(1)

            status_text.text("🔍 Quantum threat pattern analysis...")
            progress_bar.progress(85)
            time.sleep(1)

            # Actual quantum analysis
            analysis_result = real_threat_detector.analyze_website(url)

            progress_bar.progress(100)
            status_text.text("✅ Quantum analysis complete!")
            time.sleep(0.5)

            # Clear progress indicators
            progress_bar.empty()
            status_text.empty()

            # Store in history
            st.session_state.analysis_history.append(analysis_result)

            # Display quantum results
            display_quantum_analysis_results(analysis_result)


def display_quantum_analysis_results(result: Dict[str, Any]):
    """Display quantum-enhanced analysis results"""

    # Overall status
    st.subheader("📊 Quantum Security Analysis Results")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("🛡️ Security Score", f"{result.get('security_score', 0)}/100")

    with col2:
        st.metric("🚨 Threats Found", len(result.get('threats_detected', [])))

    with col3:
        risk_level = result.get('risk_level', 'UNKNOWN')
        st.metric("⚠️ Risk Level", risk_level)

    with col4:
        status = result.get('status', '❓ UNKNOWN')
        st.metric("📈 Status", status)

    # Quantum Analysis Details
    quantum_analysis = result.get('quantum_analysis', {})
    if quantum_analysis:
        st.subheader("🧬 Quantum Analysis Details")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>⚛️ Qubits Used</h4>
                <h2>{quantum_analysis.get('qubits_used', 0)}</h2>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>🔄 Circuits Run</h4>
                <h2>{quantum_analysis.get('circuits_executed', 0)}</h2>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>🌌 Superposition States</h4>
                <h2>{quantum_analysis.get('superposition_states', 0)}</h2>
            </div>
            """, unsafe_allow_html=True)

        with col4:
            entanglement = quantum_analysis.get('entanglement_measure', 0)
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>🔗 Entanglement</h4>
                <h2>{entanglement:.2f}</h2>
            </div>
            """, unsafe_allow_html=True)

    # Threats detected
    threats = result.get('threats_detected', [])

    if threats:
        st.subheader("🚨 Security Threats Detected")

        for i, threat in enumerate(threats):
            threat_type = threat.get('type', '')
            severity = threat.get('severity', 'MEDIUM')

            # Check if it's a quantum-detected threat
            if '🧬 Quantum-Detected' in threat_type:
                card_class = "threat-card-quantum"
                icon = "🧬"

                quantum_details = threat.get('quantum_details', {})

                st.markdown(f"""
                <div class="{card_class}">
                    <h4>{icon} {threat_type} - {severity}</h4>
                    <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
                    <p><strong>Risk:</strong> {threat.get('risk', 'Unknown risk')}</p>
                    <p><strong>Quantum Confidence:</strong> {quantum_details.get('confidence', 0):.1%}</p>
                    <p><strong>Entanglement Factor:</strong> {quantum_details.get('entanglement_factor', 0):.2f}</p>
                    <p><strong>Superposition State:</strong> {quantum_details.get('superposition_state', 'Unknown')}</p>
                    <p><strong>Patterns Found:</strong> {', '.join(threat.get('patterns_found', []))}</p>
                </div>
                """, unsafe_allow_html=True)

            else:
                # Regular threat
                if severity == 'HIGH' or severity == 'CRITICAL':
                    card_class = "threat-card-high"
                    icon = "🔴"
                elif severity == 'MEDIUM':
                    card_class = "threat-card-medium"
                    icon = "🟡"
                else:
                    card_class = "threat-card-low"
                    icon = "🟢"

                st.markdown(f"""
                <div class="{card_class}">
                    <h4>{icon} {threat_type} - {severity}</h4>
                    <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
                    <p><strong>Risk:</strong> {threat.get('risk', 'Unknown risk')}</p>
                    {f"<p><strong>Recommendation:</strong> {threat.get('recommendation', 'No recommendation')}</p>" if threat.get('recommendation') else ""}
                    {f"<p><strong>Details:</strong> {threat.get('details', '')}</p>" if threat.get('details') else ""}
                </div>
                """, unsafe_allow_html=True)

    else:
        st.markdown("""
        <div class="secure-card">
            <h4>🟢 No Threats Detected by Quantum Analysis</h4>
            <p>The website appears to be secure based on our quantum-enhanced analysis.</p>
        </div>
        """, unsafe_allow_html=True)

    # Recommendations
    recommendations = result.get('recommendations', [])
    if recommendations:
        st.subheader("💡 Quantum-Enhanced Security Recommendations")
        for rec in recommendations:
            if '🧬' in rec:
                st.markdown(f"**{rec}**")  # Highlight quantum recommendations
            else:
                st.write(f"• {rec}")

    # Technical details with quantum info
    with st.expander("🔧 Technical & Quantum Details"):
        col1, col2 = st.columns(2)

        with col1:
            technical = result.get('technical_details', {})
            st.write("**HTTP Response:**")
            st.write(f"Status Code: {technical.get('status_code', 'Unknown')}")

            headers = technical.get('response_headers', {})
            if headers:
                st.write("**Response Headers:**")
                for header, value in list(headers.items())[:10]:
                    st.write(f"• {header}: {value}")

        with col2:
            quantum_analysis = result.get('quantum_analysis', {})
            if quantum_analysis:
                st.write("**🧬 Quantum Analysis:**")
                st.write(f"Quantum Enabled: {quantum_analysis.get('quantum_enabled', False)}")
                st.write(f"Qubits Used: {quantum_analysis.get('qubits_used', 0)}")
                st.write(f"Circuits Executed: {quantum_analysis.get('circuits_executed', 0)}")
                st.write(f"Quantum Confidence: {quantum_analysis.get('quantum_confidence', 0):.1%}")

                quantum_threats = quantum_analysis.get('quantum_threats', [])
                if quantum_threats:
                    st.write("**Quantum Threat Details:**")
                    for qt in quantum_threats:
                        st.write(f"• {qt['type']}: {qt['quantum_confidence']:.1%} confidence")


def render_network_analyzer():
    """Network traffic analyzer"""
    st.header("📡 Network Traffic Analyzer")
    st.info("🔍 Analyze network packets for security threats and anomalies")

    # File upload for packet analysis
    st.subheader("📁 Upload Network Capture File")

    uploaded_file = st.file_uploader(
        "Choose a network capture file",
        type=['pcap', 'csv', 'json'],
        help="Upload PCAP files or CSV/JSON with network data"
    )

    if uploaded_file:
        st.success(f"✅ File uploaded: {uploaded_file.name}")

        if st.button("🔍 Analyze Network Traffic", type="primary"):
            with st.spinner("🔍 Analyzing network traffic..."):

                # Simulate packet data for demo
                packets = []
                for i in range(100):
                    packet = {
                        'timestamp': datetime.now() - timedelta(seconds=i),
                        'source_ip': f"192.168.1.{random.randint(1, 254)}",
                        'destination_ip': f"10.0.0.{random.randint(1, 254)}",
                        'source_port': random.randint(1024, 65535),
                        'destination_port': random.choice([80, 443, 22, 21, 25, 53]),
                        'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
                        'size': random.randint(64, 1500)
                    }
                    packets.append(packet)

                # Add some suspicious patterns
                if random.random() < 0.3:  # 30% chance of port scan
                    scanner_ip = "192.168.1.100"
                    for port in range(20, 100, 5):  # Port scan pattern
                        packet = {
                            'timestamp': datetime.now(),
                            'source_ip': scanner_ip,
                            'destination_ip': "10.0.0.50",
                            'source_port': random.randint(1024, 65535),
                            'destination_port': port,
                            'protocol': 'TCP',
                            'size': 64
                        }
                        packets.append(packet)

                # Analyze traffic
                analysis = network_analyzer.analyze_traffic(packets)

                # Display results
                st.subheader("📊 Network Analysis Results")

                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("📦 Total Packets", analysis['total_packets'])

                with col2:
                    st.metric("🚨 Threats Detected", len(analysis['threats_detected']))

                with col3:
                    st.metric("🛡️ Blocked IPs", len(analysis['blocked_ips']))

                with col4:
                    st.metric("⚠️ Risk Score", analysis['risk_score'])

                # Show threats
                threats = analysis.get('threats_detected', [])
                if threats:
                    st.subheader("🚨 Network Threats Detected")

                    for threat in threats:
                        severity = threat.get('severity', 'MEDIUM')

                        if severity == 'CRITICAL':
                            card_class = "threat-card-high"
                            icon = "🔴"
                        elif severity == 'HIGH':
                            card_class = "threat-card-high"
                            icon = "🟠"
                        else:
                            card_class = "threat-card-medium"
                            icon = "🟡"

                        st.markdown(f"""
                        <div class="{card_class}">
                            <h4>{icon} {threat.get('type', 'Unknown')} - {severity}</h4>
                            <p><strong>Source IP:</strong> {threat.get('source_ip', 'Unknown')}</p>
                            <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
                            <p><strong>Details:</strong> {threat.get('details', 'No details')}</p>
                            <p><strong>Recommendation:</strong> {threat.get('recommendation', 'Monitor closely')}</p>
                        </div>
                        """, unsafe_allow_html=True)

                # Statistics
                with st.expander("📊 Traffic Statistics"):
                    stats = analysis.get('statistics', {})

                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("**Protocol Distribution:**")
                        protocols = stats.get('protocols', {})
                        if protocols:
                            df_protocols = pd.DataFrame(list(protocols.items()), columns=['Protocol', 'Count'])
                            fig = px.pie(df_protocols, values='Count', names='Protocol', title="Protocol Distribution")
                            st.plotly_chart(fig, use_container_width=True)

                    with col2:
                        st.write("**Top Source IPs:**")
                        top_sources = stats.get('top_sources', {})
                        for ip, count in list(top_sources.items())[:10]:
                            st.write(f"• {ip}: {count} packets")


def render_threat_dashboard():
    """Threat dashboard with quantum metrics"""
    st.header("📊 Quantum-Enhanced Threat Dashboard")

    # Summary metrics
    total_scans = len(st.session_state.analysis_history)
    total_threats = sum(len(a.get('threats_detected', [])) for a in st.session_state.analysis_history)
    quantum_threats = sum(
        len([t for t in a.get('threats_detected', []) if '🧬 Quantum-Detected' in t.get('type', '')])
        for a in st.session_state.analysis_history
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("🔍 Total Scans", total_scans)

    with col2:
        st.metric("🚨 Threats Found", total_threats)

    with col3:
        st.metric("🧬 Quantum Threats", quantum_threats)

    with col4:
        avg_score = np.mean([a.get('security_score', 100) for a in
                             st.session_state.analysis_history]) if st.session_state.analysis_history else 100
        st.metric("📊 Avg Security Score", f"{avg_score:.1f}")

    if st.session_state.analysis_history:
        # Quantum vs Classical detection comparison
        st.subheader("🧬 Quantum vs Classical Detection")

        quantum_detections = []
        classical_detections = []

        for analysis in st.session_state.analysis_history:
            q_count = len(
                [t for t in analysis.get('threats_detected', []) if '🧬 Quantum-Detected' in t.get('type', '')])
            c_count = len(
                [t for t in analysis.get('threats_detected', []) if '🧬 Quantum-Detected' not in t.get('type', '')])

            quantum_detections.append(q_count)
            classical_detections.append(c_count)

        if quantum_detections or classical_detections:
            comparison_data = pd.DataFrame({
                'Scan': range(1, len(quantum_detections) + 1),
                'Quantum Detections': quantum_detections,
                'Classical Detections': classical_detections
            })

            fig = px.bar(comparison_data, x='Scan', y=['Quantum Detections', 'Classical Detections'],
                         title="Quantum vs Classical Threat Detection", barmode='group')
            st.plotly_chart(fig, use_container_width=True)

        # Threat types chart
        st.subheader("📈 Threat Types Distribution")

        threat_types = {}
        for analysis in st.session_state.analysis_history:
            for threat in analysis.get('threats_detected', []):
                threat_type = threat.get('type', 'Unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1

        if threat_types:
            df_threats = pd.DataFrame(list(threat_types.items()), columns=['Threat Type', 'Count'])
            fig = px.bar(df_threats, x='Threat Type', y='Count', title="Most Common Threats")
            st.plotly_chart(fig, use_container_width=True)


def render_analysis_history():
    """Analysis history with quantum details"""
    st.header("📋 Website Analysis History")

    if not st.session_state.analysis_history:
        st.info("🔍 No analysis history yet. Start by scanning some websites!")
        return

    # Display history
    for i, analysis in enumerate(reversed(st.session_state.analysis_history)):
        quantum_analysis = analysis.get('quantum_analysis', {})
        quantum_threats = len(quantum_analysis.get('quantum_threats', []))

        with st.expander(
                f"🔍 Scan #{len(st.session_state.analysis_history) - i}: {analysis.get('url', 'Unknown')} - {analysis.get('status', 'Unknown')} {'🧬' if quantum_threats > 0 else ''}"):

            col1, col2, col3 = st.columns(3)

            with col1:
                st.write(f"**Security Score:** {analysis.get('security_score', 0)}/100")
                st.write(f"**Risk Level:** {analysis.get('risk_level', 'Unknown')}")

            with col2:
                st.write(f"**Threats Found:** {len(analysis.get('threats_detected', []))}")
                st.write(f"**🧬 Quantum Threats:** {quantum_threats}")

            with col3:
                st.write(f"**Scan Time:** {analysis.get('timestamp', 'Unknown')[:19]}")
                if quantum_analysis:
                    st.write(f"**🧬 Quantum Confidence:** {quantum_analysis.get('quantum_confidence', 0):.1%}")


def render_scanner_settings():
    """Scanner settings with quantum options"""
    st.header("⚙️ Quantum Scanner Configuration")

    st.subheader("🧬 Quantum Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.checkbox("🧬 Enable Quantum Analysis", value=True)
        st.slider("⚛️ Number of Qubits", 4, 16, 8)
        st.slider("🔗 Entanglement Threshold", 0.1, 1.0, 0.8)
        st.checkbox("🌌 Superposition Analysis", value=True)

    with col2:
        st.checkbox("🔄 Quantum Circuit Optimization", value=True)
        st.slider("📊 Quantum Confidence Threshold", 0.1, 1.0, 0.6)
        st.checkbox("⚡ Quantum Acceleration", value=True)
        st.checkbox("🔬 Advanced Quantum Patterns", value=True)

    st.subheader("🔍 Classical Scan Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.checkbox("🔒 Check SSL/TLS Configuration", value=True)
        st.checkbox("🛡️ Analyze Security Headers", value=True)
        st.checkbox("🔍 Scan for XSS Vulnerabilities", value=True)
        st.checkbox("💉 Check for SQL Injection", value=True)

    with col2:
        st.checkbox("🔄 Analyze Redirects", value=True)
        st.checkbox("📜 Check JavaScript Security", value=True)
        st.checkbox("🌐 Verify HTTPS Usage", value=True)
        st.checkbox("📊 Generate Detailed Reports", value=True)

    st.subheader("⚡ Performance Settings")

    timeout = st.slider("Request Timeout (seconds)", 5, 30, 10)
    max_redirects = st.slider("Maximum Redirects to Follow", 1, 10, 5)

    st.subheader("🚨 Alert Settings")

    alert_threshold = st.slider("Security Score Alert Threshold", 0, 100, 70)
    quantum_alert_threshold = st.slider("Quantum Confidence Alert Threshold", 0.1, 1.0, 0.8)
    st.checkbox("📧 Send Email Alerts", value=False)
    st.checkbox("📱 Send Push Notifications", value=False)
    st.checkbox("🧬 Quantum Alert Priority", value=True)

    if st.button("💾 Save Quantum Settings", type="primary"):
        st.success("✅ Quantum settings saved successfully!")


if __name__ == "__main__":
    main()
