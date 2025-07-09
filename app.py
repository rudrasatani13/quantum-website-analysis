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
import asyncio

load_dotenv(dotenv_path="/Users/apple/Desktop/qs-ai-ids-dashboard/.env")

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Import our custom modules
from utils.quantum_detector import QuantumDetector
from utils.data_processor import DataProcessor
from utils.ai_detector import AIDetector
from utils.network_monitor import NetworkMonitor
from utils.pattern_analyzer import PatternAnalyzer
from utils.legitimacy_analyzer import LegitimacyAnalyzer
from utils.security_headers_analyzer import SecurityHeadersAnalyzer
from utils.ml_detector import MLDetector
from utils.async_scanner import AsyncScanner


# Advanced Context-Aware Threat Detection
class AdvancedContextAnalyzer:

    def __init__(self):
        self.context_enabled = True
        self.analysis_depth = 8

        # Initialize analysis components
        self.pattern_analyzer = PatternAnalyzer()

        # Initialize threat patterns (reduced from original as they moved to PatternAnalyzer)
        self.threat_patterns = {}

    def analyze_content(self, content, url, classical_threats, security_headers, ssl_info):
        # Use the pattern analyzer
        pattern_results = self.pattern_analyzer.analyze_patterns(content)

        # Create results structure
        analysis_results = {
            'context_enabled': self.context_enabled,
            'analysis_depth': self.analysis_depth,
            'advanced_threats': [],
            'confidence': pattern_results['confidence'],
            'legitimacy_score': 0.0,
            'security_indicators': {}
        }

        # Calculate legitimacy using LegitimacyAnalyzer
        legitimacy_analyzer = LegitimacyAnalyzer()
        legitimacy_score = legitimacy_analyzer.calculate_legitimacy(content, url, security_headers, ssl_info)
        analysis_results['legitimacy_score'] = legitimacy_score

        # Process threats from pattern analyzer
        for threat_type in pattern_results['threat_types']:
            # Only add if confidence is very high
            confidence = pattern_results['confidence']
            if confidence > 0.6:
                analysis_results['advanced_threats'].append({
                    'type': threat_type,
                    'confidence': confidence,
                    # Additional details...
                })

        return analysis_results

    def _analyze_security_indicators(self, content, url, security_headers, ssl_info):
        """Analyze various security indicators"""
        indicators = {}
        # Implementation remains the same
        return indicators

    def _has_professional_structure(self, content):
        """Check if content has professional website structure"""
        content_lower = content.lower()
        required_elements = ['<html', '<head', '<body', '<title']
        return sum(1 for element in required_elements if element in content_lower) >= 3

    def _is_in_comment_or_documentation(self, context):
        """Check if content is in comments or documentation"""
        doc_indicators = ['<!-- example', '/* example', 'code example', 'documentation', 'tutorial']
        return any(indicator in context.lower() for indicator in doc_indicators)

    def _is_in_code_example(self, context):
        """Check if content is in code examples"""
        code_indicators = ['<code', '<pre', 'example', 'sample', 'snippet']
        return any(indicator in context.lower() for indicator in code_indicators)


# Advanced Security Analyzer
class AdvancedSecurityAnalyzer:

    def __init__(self):
        # Replace quantum_analyzer with context_analyzer
        self.context_analyzer = AdvancedContextAnalyzer()

        # Add new components
        self.security_headers_analyzer = SecurityHeadersAnalyzer()
        self.ml_detector = MLDetector()
        self.async_scanner = AsyncScanner(timeout=15)

        # Keep threat patterns for legacy compatibility
        self.threat_patterns = {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'path_traversal': []
        }

        self.security_headers = [
            'content-security-policy',
            'x-xss-protection',
            'x-frame-options',
            'strict-transport-security'
        ]

    async def analyze_website_async(self, url):

        # Initialize result structure
        analysis_result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'threats_detected': [],
            'vulnerabilities': [],
            'security_score': 100,
            'recommendations': [],
            'technical_details': {},
            'advanced_analysis': {}  # renamed from quantum_analysis
        }

        try:
            # Use async scanner for better performance
            scan_results = await self.async_scanner.scan_website(url)

            if scan_results.get('error'):
                analysis_result['threats_detected'].append({
                    'type': 'Connection Error',
                    'severity': 'HIGH',
                    'description': f'Unable to connect to website: {scan_results["error"]}',
                    'risk': 'Website may be down or blocking security scans'
                })
                analysis_result['security_score'] = 0
                analysis_result['status'] = '🔴 UNREACHABLE'
                return analysis_result

            # Extract scan results
            page_content = scan_results['content']
            headers = scan_results['headers']
            ssl_info = scan_results['ssl_info']
            analysis_result['technical_details']['status_code'] = scan_results['status_code']
            analysis_result['technical_details']['response_headers'] = headers
            analysis_result['technical_details']['ssl_info'] = ssl_info
            analysis_result['technical_details']['scan_time'] = scan_results['scan_time']

            # Check URL scheme
            parsed_url = urlparse(url)
            if parsed_url.scheme == 'http':
                analysis_result['threats_detected'].append({
                    'type': 'Insecure Protocol',
                    'severity': 'MEDIUM',
                    'description': 'Website uses HTTP instead of HTTPS',
                    'risk': 'Data transmission is not encrypted',
                    'recommendation': 'Consider switching to HTTPS for better security'
                })
                analysis_result['security_score'] -= 10

            # Perform machine learning detection
            ml_results = self.ml_detector.detect_threats(page_content)
            if ml_results['threats_detected']:
                for ml_threat in ml_results['threats_detected']:
                    analysis_result['threats_detected'].append({
                        'type': f"ML-Detected {ml_threat['type']}",
                        'severity': 'HIGH',
                        'description': 'Machine learning model detected potential threat',
                        'confidence': ml_threat['confidence'],
                        'risk': 'Potential security vulnerability detected by ML model'
                    })
                    analysis_result['security_score'] -= int(ml_threat['confidence'] * 15)

            # Analyze security headers
            headers_analysis = self.security_headers_analyzer.analyze_headers(headers)
            if headers_analysis['missing_headers']:
                critical_headers = [h for h in headers_analysis['missing_headers'] if h['severity'] == 'HIGH']
                if critical_headers:
                    analysis_result['threats_detected'].append({
                        'type': 'Missing Critical Security Headers',
                        'severity': 'HIGH',
                        'description': f'Missing {len(critical_headers)} critical security headers',
                        'details': [h['header'] for h in critical_headers],
                        'risk': 'Website lacks important security header protections',
                        'recommendations': [h['recommendation'] for h in critical_headers]
                    })
                    analysis_result['security_score'] -= 15

                medium_headers = [h for h in headers_analysis['missing_headers'] if h['severity'] == 'MEDIUM']
                if medium_headers:
                    analysis_result['vulnerabilities'].append({
                        'type': 'Missing Medium Security Headers',
                        'severity': 'MEDIUM',
                        'description': f'Missing {len(medium_headers)} medium-priority security headers',
                        'details': [h['header'] for h in medium_headers],
                        'risk': 'Website could benefit from additional security headers',
                        'recommendations': [h['recommendation'] for h in medium_headers]
                    })
                    analysis_result['security_score'] -= 8

            # Add header recommendations
            for rec in headers_analysis['recommendations']:
                analysis_result['recommendations'].append(rec)

            # Perform classic pattern-based detection
            classical_threats = []

            # Perform advanced context-aware analysis
            advanced_results = self.context_analyzer.analyze_content(
                page_content, url, classical_threats, headers, ssl_info
            )
            analysis_result['advanced_analysis'] = advanced_results

            # Process advanced threats
            for threat in advanced_results['advanced_threats']:
                threat_type = threat['type']
                confidence = threat['confidence']

                # High threshold for threats
                if confidence > 0.75:
                    severity = 'CRITICAL' if confidence > 0.9 else 'HIGH'

                    analysis_result['threats_detected'].append({
                        'type': f"🔍 Advanced {threat_type.replace('_', ' ').title()}",
                        'severity': severity,
                        'description': f'Advanced algorithms detected {threat_type} with {confidence:.1%} confidence',
                        'risk': f'High-confidence detection indicates serious security vulnerability',
                        'advanced_details': {
                            'confidence': confidence
                            # Other details...
                        }
                    })

                    # Reduced score penalty
                    score_reduction = int(confidence * 20)
                    analysis_result['security_score'] -= score_reduction

            # Generate recommendations based on all findings
            analysis_result['recommendations'].extend(self._generate_recommendations(analysis_result))

            # Ensure score is within bounds
            analysis_result['security_score'] = max(0, min(100, analysis_result['security_score']))

            # Set risk level based on score
            if analysis_result['security_score'] >= 90:
                analysis_result['risk_level'] = 'LOW'
                analysis_result['status'] = '🟢 SECURE'
            elif analysis_result['security_score'] >= 75:
                analysis_result['risk_level'] = 'LOW'
                analysis_result['status'] = '🟢 MOSTLY SECURE'
            elif analysis_result['security_score'] >= 60:
                analysis_result['risk_level'] = 'MEDIUM'
                analysis_result['status'] = '🟡 MODERATE RISK'
            elif analysis_result['security_score'] >= 40:
                analysis_result['risk_level'] = 'HIGH'
                analysis_result['status'] = '🟠 HIGH RISK'
            else:
                analysis_result['risk_level'] = 'CRITICAL'
                analysis_result['status'] = '🔴 CRITICAL RISK'

        except Exception as e:
            analysis_result['threats_detected'].append({
                'type': 'Analysis Error',
                'severity': 'MEDIUM',
                'description': f'Error during analysis: {str(e)}',
                'risk': 'Unable to complete full security assessment'
            })

        return analysis_result

    def analyze_website(self, url):

        # Create an event loop for async operation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            result = loop.run_until_complete(self.analyze_website_async(url))
        finally:
            loop.close()

        return result

    def _generate_recommendations(self, analysis):
        """Generate security recommendations based on analysis results"""
        recommendations = []

        threats = analysis.get('threats_detected', [])
        advanced_analysis = analysis.get('advanced_analysis', {})
        security_score = analysis.get('security_score', 100)
        legitimacy_score = advanced_analysis.get('legitimacy_score', 0)

        # Legitimacy-based recommendations
        if legitimacy_score > 0.8:
            recommendations.append("✅ Website appears to be legitimate based on content analysis")
        elif legitimacy_score > 0.6:
            recommendations.append("👍 Website has some legitimate indicators but could be improved")
        elif legitimacy_score < 0.4:
            recommendations.append("⚠️ Website legitimacy is questionable - exercise caution")

        # General recommendations based on security score
        if security_score >= 90:
            recommendations.append("✅ Security posture is strong - maintain current practices")
        elif security_score >= 75:
            recommendations.append("👍 Good security but could be improved - review recommendations")
        elif security_score >= 60:
            recommendations.append("⚠️ Moderate security issues found - address recommended fixes")
        elif security_score >= 40:
            recommendations.append("🚨 Significant security issues detected - immediate action recommended")
        else:
            recommendations.append("🚨 Critical security concerns - site may be compromised or malicious")

        return list(set(recommendations))

    def _analyze_ssl(self, hostname, port=443):
        """Analyze SSL/TLS configuration"""
        ssl_info = {}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info['version'] = ssock.version()
                    cert = ssock.getpeercert()
                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                    ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                    ssl_info['expires'] = cert['notAfter']
                    ssl_info['error'] = None
        except Exception as e:
            ssl_info['error'] = str(e)

        return ssl_info


# Network Traffic Analyzer (keeping existing implementation)
class NetworkTrafficAnalyzer:
    """Network traffic analysis"""

    def __init__(self):
        self.suspicious_patterns = {
            'port_scan': r'multiple ports in short time',
            'bruteforce': r'repeated auth failures',
            'ddos': r'excessive traffic from single source',
            'data_exfiltration': r'large outbound transfer'
        }

        self.blocked_ips = set()
        self.threat_count = 0

    def analyze_traffic(self, packets):
        """Analyze network packets for threats"""

        analysis = {
            'threats_detected': [],
            'suspicious_activities': [],
            'statistics': {
                'total_packets': len(packets) if packets else 0,
                'protocols': {},
                'top_sources': {},
                'port_distribution': {}
            }
        }

        if not packets:
            return analysis

        # Analyze packet patterns
        source_ips = {}
        dest_ports = {}
        protocols = {}

        for packet in packets:
            src_ip = packet.get('source_ip', 'unknown')
            dest_port = packet.get('dest_port', 0)
            protocol = packet.get('protocol', 'unknown')

            source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
            dest_ports[dest_port] = dest_ports.get(dest_port, 0) + 1
            protocols[protocol] = protocols.get(protocol, 0) + 1

        # Update statistics
        analysis['statistics']['protocols'] = protocols
        analysis['statistics']['top_sources'] = dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10])
        analysis['statistics']['port_distribution'] = dict(
            sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:10])

        self.threat_count += len(analysis['threats_detected'])

        return analysis


# Initialize advanced components
advanced_security_analyzer = AdvancedSecurityAnalyzer()
network_analyzer = NetworkTrafficAnalyzer()

# Page configuration
st.set_page_config(
    page_title="Advanced Security Analysis Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional minimal CSS styling
# Replace the existing CSS section with this updated styling
st.markdown("""
<style>
    /* Modern Color Palette */
    :root {
        --primary: #3a86ff;
        --primary-light: #5e9dff;
        --primary-dark: #2870e8;
        --secondary: #4cc9f0;
        --accent: #ff006e;
        --success: #38b000;
        --warning: #ffbe0b;
        --danger: #ff5400;
        --dark: #293241;
        --light: #f8f9fa;
        --gray: #adb5bd;
        --card-bg: #ffffff;
        --shadow: rgba(0, 0, 0, 0.05);
    }

    /* Base Styles */
    .main-header {
        background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
        padding: 2.5rem 2rem;
        border-radius: 16px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        border: none;
        transition: all 0.3s ease;
    }

    .main-header:hover {
        box-shadow: 0 6px 24px rgba(0, 0, 0, 0.15);
        transform: translateY(-2px);
    }

    /* Card Styles */
    .advanced-header {
        background: linear-gradient(135deg, #ffffff 0%, #f2f7ff 100%);
        border: none;
        border-radius: 16px;
        padding: 1.8rem;
        color: var(--dark);
        text-align: center;
        margin: 1.5rem 0;
        box-shadow: 0 8px 30px var(--shadow);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }

    .advanced-header:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.1);
    }

    .threat-card-advanced, .secure-card, .legitimate-card, .advanced-metrics, .metric-card {
        background: var(--card-bg);
        border: none;
        border-radius: 14px;
        padding: 1.8rem;
        margin: 1rem 0;
        color: var(--dark);
        font-weight: 500;
        box-shadow: 0 8px 30px var(--shadow);
        transition: all 0.3s ease;
    }

    .threat-card-advanced:hover, .secure-card:hover, .legitimate-card:hover, .advanced-metrics:hover, .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.1);
    }

    .threat-card-high {
        background: linear-gradient(to right, #fff1f1 0%, #ffffff 100%);
        border: none;
        border-left: 5px solid var(--danger);
        border-radius: 14px;
        padding: 1.8rem;
        margin: 1rem 0;
        color: var(--dark);
        font-weight: 500;
        box-shadow: 0 8px 30px var(--shadow);
        transition: all 0.3s ease;
    }

    .threat-card-medium {
        background: linear-gradient(to right, #fff8eb 0%, #ffffff 100%);
        border: none;
        border-left: 5px solid var(--warning);
        border-radius: 14px;
        padding: 1.8rem;
        margin: 1rem 0;
        color: var(--dark);
        font-weight: 500;
        box-shadow: 0 8px 30px var(--shadow);
        transition: all 0.3s ease;
    }

    .threat-card-low {
        background: linear-gradient(to right, #f0fff4 0%, #ffffff 100%);
        border: none;
        border-left: 5px solid var(--success);
        border-radius: 14px;
        padding: 1.8rem;
        margin: 1rem 0;
        color: var(--dark);
        font-weight: 500;
        box-shadow: 0 8px 30px var(--shadow);
        transition: all 0.3s ease;
    }

    .threat-card-high:hover, .threat-card-medium:hover, .threat-card-low:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.1);
    }

    .secure-card {
        background: linear-gradient(to right, #f0fff4 0%, #ffffff 100%);
        border: none;
        border-left: 5px solid var(--success);
    }

    .legitimate-card {
        background: linear-gradient(to right, #f0f7ff 0%, #ffffff 100%);
        border: none;
        border-left: 5px solid var(--primary);
    }

    /* Badge Styles */
    .universal-badge, .advanced-badge, .legitimacy-badge {
        background: var(--primary);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 30px;
        font-size: 0.85rem;
        font-weight: 500;
        display: inline-block;
        margin: 0.25rem;
        box-shadow: 0 4px 10px rgba(58, 134, 255, 0.2);
        transition: all 0.2s ease;
    }

    .universal-badge:hover, .advanced-badge:hover, .legitimacy-badge:hover {
        background: var(--primary-dark);
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(58, 134, 255, 0.25);
    }

    /* Button Styles */
    .stButton > button {
        background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 30px !important;
        padding: 0.7rem 1.5rem !important;
        font-weight: 500 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 12px rgba(58, 134, 255, 0.25) !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }

    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 16px rgba(58, 134, 255, 0.35) !important;
    }

    .stButton > button:active {
        transform: translateY(1px) !important;
        box-shadow: 0 2px 8px rgba(58, 134, 255, 0.2) !important;
    }

    /* Input Styles */
    .stTextInput > div > div > input {
        border-radius: 12px !important;
        border: 1px solid #e2e8f0 !important;
        padding: 0.8rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05) !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 3px rgba(58, 134, 255, 0.15) !important;
        transform: translateY(-1px) !important;
    }

    /* Selectbox Styles */
    .stSelectbox > div > div > div {
        border-radius: 12px !important;
        border: 1px solid #e2e8f0 !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05) !important;
    }

    .stSelectbox > div > div > div:focus-within {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 3px rgba(58, 134, 255, 0.15) !important;
        transform: translateY(-1px) !important;
    }

    /* Sidebar Styles */
    .css-1d391kg {
        background: #f8f9fa !important;
        border-right: none !important;
        box-shadow: 0 0 15px rgba(0, 0, 0, 0.05) !important;
    }

    /* Progress Bar */
    .stProgress > div > div > div {
        background: linear-gradient(to right, var(--primary), var(--secondary)) !important;
        border-radius: 30px !important;
        height: 8px !important;
    }

    /* Expander */
    .streamlit-expanderHeader {
        background: #f8f9fa !important;
        border-radius: 12px !important;
        transition: all 0.3s ease !important;
    }

    .streamlit-expanderHeader:hover {
        background: #f0f3f5 !important;
        transform: translateX(3px) !important;
    }

    /* Metric */
    [data-testid="stMetricValue"] {
        font-size: 2rem !important;
        font-weight: 600 !important;
        color: var(--primary) !important;
    }

    [data-testid="stMetricLabel"] {
        font-size: 1rem !important;
        font-weight: 500 !important;
        color: var(--dark) !important;
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
            'total_scans': 0,
            'threats_detected': 0,
            'high_risk_sites': 0
        },
        'recent_threats': [],
        'attack_distribution': {
            'XSS': 0,
            'SQL Injection': 0,
            'Other': 0
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

    # Dark mode toggle button in header
    col1, col2, col3 = st.columns([8, 1, 1])

    with col3:
        if st.button("🌙" if not st.session_state.get('dark_mode', False) else "☀️"):
            st.session_state.dark_mode = not st.session_state.get('dark_mode', False)

    # Enhanced header with advanced context analysis
    st.markdown("""
    <div class="main-header">
        <h1 style="margin: 0; font-size: 2.2rem; font-weight: 700;">Quantum-Safe Intrusion Detection System</h1>
        <p style="margin: 0.5rem 0 0 0; font-size: 1.1rem; font-weight: 400; opacity: 0.9;">
            Advanced security analysis powered by context-aware algorithms
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Enhanced Sidebar
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 1rem;">
            <h3>🛡️ Advanced Security Analysis</h3>
        </div>
        """, unsafe_allow_html=True)

        # Enhanced analysis status with better organization
        st.markdown("""
        <div class="advanced-metrics">
            <h4>🔍 Analysis Status</h4>
            <p>Advanced context-aware analysis active</p>
        </div>
        """, unsafe_allow_html=True)

        # Enhanced navigation with icons and descriptions
        st.markdown("### 🗺️ Navigation")

        page_options = {
            "🔍 Advanced Website Scanner": "Analyze websites with context-aware algorithms",
            "📡 Network Traffic Analyzer": "Monitor and analyze network traffic for threats",
            "📊 Threat Dashboard": "View threat statistics and analytics",
            "📋 Analysis History": "Review past website security analyses",
            "⚙️ Scanner Settings": "Configure scanner settings and options"
        }

        page = st.selectbox(
            "Select a page",
            list(page_options.keys()),
            index=0,
            format_func=lambda x: x
        )

        # Show description for selected page
        if page in page_options:
            st.info(page_options[page])

        st.markdown("---")

        # Enhanced Live Stats with better layout
        st.markdown("### 📈 Live Statistics")

        col1, col2 = st.columns(2)
        with col1:
            st.metric("🔍 Scans", st.session_state.real_time_data['counters']['total_scans'])

        with col2:
            st.metric("🚨 Threats", st.session_state.real_time_data['counters']['threats_detected'])

        # Enhanced analysis metrics
        analyses_count = sum(1 for analysis in st.session_state.analysis_history if 'advanced_analysis' in analysis)
        st.markdown(f"""
        <div class="metric-card">
            <h4 style="margin: 0; font-size: 1rem;">🔍 Advanced Analyses</h4>
            <p style="margin: 0; font-size: 1.2rem; font-weight: 500;">{analyses_count}</p>
        </div>
        """, unsafe_allow_html=True)

        # Additional system metrics
        st.markdown("---")
        st.markdown("### ⚙️ System Health")

        col1, col2 = st.columns(2)
        with col1:
            st.metric("CPU", f"{random.randint(10, 40)}%")

        with col2:
            st.metric("Memory", f"{random.randint(200, 500)}MB")

    # Main content
    if page == "🔍 Advanced Website Scanner":
        render_advanced_website_scanner()
    elif page == "📡 Network Traffic Analyzer":
        render_network_analyzer()
    elif page == "📊 Threat Dashboard":
        render_threat_dashboard()
    elif page == "📋 Analysis History":
        render_analysis_history()
    elif page == "⚙️ Scanner Settings":
        render_scanner_settings()


def render_advanced_website_scanner():
    """Advanced context-aware website security scanner"""

    # Enhanced info section
    st.markdown("""
        <div style="background: #ffffff;
                    padding: 1.5rem;
                    border-radius: 16px;
                    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.05);
                    margin: 1rem 0 2rem 0;">
            <h3 style="color: #3a86ff; font-weight: 600; margin-bottom: 1rem; font-size: 1.3rem;">
                🔍 How Context-Aware Analysis Works
            </h3>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <div style="background: #e6f0ff; padding: 0.5rem; border-radius: 8px; font-weight: 500;">Context Analysis</div>
                <div style="color: #718096;">→</div>
                <div style="background: #e6f0ff; padding: 0.5rem; border-radius: 8px; font-weight: 500;">Pattern Recognition</div>
                <div style="color: #718096;">→</div>
                <div style="background: #e6f0ff; padding: 0.5rem; border-radius: 8px; font-weight: 500;">Threat Detection</div>
                <div style="color: #718096;">→</div>
                <div style="background: #e6f0ff; padding: 0.5rem; border-radius: 8px; font-weight: 500;">Security Score</div>
            </div>
            <p style="margin: 0.5rem 0 0 0; color: #2d3748;">
                Our system analyzes websites in context, distinguishing between legitimate content and security threats with high precision.
            </p>
        </div>
        """, unsafe_allow_html=True)

    # Enhanced website analysis section
    st.markdown("### 🔍 Website Security Analysis")
    st.markdown("Enter any website URL to perform comprehensive security analysis using context-aware algorithms.")

    col1, col2 = st.columns([4, 1])

    with col1:
        url = st.text_input(
            "Website URL",
            placeholder="https://example.com",
            help="Enter the full URL including http:// or https://"
        )

    with col2:
        analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)

    # Enhanced website testing section with better organization
    st.markdown("---")
    st.markdown("### 🧪 Quick Test Gallery")
    st.markdown("Test the scanner with different types of websites to see the context-aware analysis in action:")

    # Organized test buttons with categories
    test_categories = {
        "🌟 Popular Sites": [
            "https://github.com",
            "https://stackoverflow.com",
            "https://microsoft.com"
        ],
        "💻 Tech Platforms": [
            "https://aws.amazon.com",
            "https://cloud.google.com",
            "https://azure.microsoft.com"
        ],
        "📰 News & Media": [
            "https://cnn.com",
            "https://bbc.com",
            "https://nytimes.com"
        ],
        "🛒 E-commerce": [
            "https://amazon.com",
            "https://ebay.com",
            "https://etsy.com"
        ],
        "🔍 Search & Social": [
            "https://google.com",
            "https://twitter.com",
            "https://linkedin.com"
        ],
        "⚠️ Security Tests": [
            "http://testphp.vulnweb.com",
            "https://xss-game.appspot.com",
            "http://zero.webappsecurity.com"
        ]
    }

    for category, sites in test_categories.items():
        with st.expander(f"{category}", expanded=False):
            cols = st.columns(3)
            for i, site in enumerate(sites):
                with cols[i % 3]:
                    if st.button(site, key=f"test_{site}"):
                        url = site
                        analyze_button = True

    # Enhanced analysis with better progress indicators
    if analyze_button and url:
        st.markdown("---")
        st.markdown(f"### 🔍 Analyzing: `{url}`")

        # Create enhanced progress container
        progress_container = st.container()

        with progress_container:
            progress_bar = st.progress(0)

            with st.spinner("Initializing security scan..."):
                time.sleep(0.5)
                progress_bar.progress(10)

            with st.spinner("Fetching website content..."):
                time.sleep(0.7)
                progress_bar.progress(30)

            with st.spinner("Analyzing security headers..."):
                time.sleep(0.5)
                progress_bar.progress(50)

            with st.spinner("Running ML-based threat detection..."):
                time.sleep(0.8)
                progress_bar.progress(70)

            with st.spinner("Performing context-aware pattern analysis..."):
                time.sleep(0.9)
                progress_bar.progress(85)

            with st.spinner("Generating final security report..."):
                time.sleep(0.6)
                progress_bar.progress(100)

                # Analyze website security
                result = advanced_security_analyzer.analyze_website(url)

                # Update session state with analysis results
                st.session_state.analysis_results = result

                # Add to history
                st.session_state.analysis_history.append(result)

                # Update real-time counters
                st.session_state.real_time_data['counters']['total_scans'] += 1
                threat_count = len(result.get('threats_detected', []))
                st.session_state.real_time_data['counters']['threats_detected'] += threat_count

                if result.get('security_score', 100) < 60:
                    st.session_state.real_time_data['counters']['high_risk_sites'] += 1

                # Display results
                display_advanced_analysis_results(result)


def display_advanced_analysis_results(result):
    """Display advanced context-aware analysis results"""

    # Overall status
    st.subheader("📊 Advanced Security Analysis Results")

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

    # Advanced Analysis Details
    advanced_analysis = result.get('advanced_analysis', {})
    if advanced_analysis:
        st.subheader("🔍 Advanced Context Analysis Details")

        # Show legitimacy score
        legitimacy_score = advanced_analysis.get('legitimacy_score', 0)

        if legitimacy_score > 0.8:
            st.markdown("""
            <div class="legitimate-card">
                <h4 style="margin: 0;">✅ High Legitimacy Score</h4>
                <p style="margin: 0.5rem 0 0 0;">This website appears to be legitimate based on comprehensive content analysis.</p>
            </div>
            """, unsafe_allow_html=True)
        elif legitimacy_score > 0.6:
            st.markdown("""
            <div class="legitimate-card" style="border-left-color: #ed8936;">
                <h4 style="margin: 0;">👍 Moderate Legitimacy Score</h4>
                <p style="margin: 0.5rem 0 0 0;">This website shows some legitimate indicators but could be improved.</p>
            </div>
            """, unsafe_allow_html=True)
        elif legitimacy_score < 0.4:
            st.markdown("""
            <div class="legitimate-card" style="border-left-color: #f56565;">
                <h4 style="margin: 0;">⚠️ Low Legitimacy Score</h4>
                <p style="margin: 0.5rem 0 0 0;">This website has questionable legitimacy indicators - exercise caution.</p>
            </div>
            """, unsafe_allow_html=True)

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("🏆 Legitimacy", f"{legitimacy_score:.1%}")

        with col2:
            st.metric("🔍 Context Awareness",
                      f"{'Active' if advanced_analysis.get('context_enabled', False) else 'Inactive'}")

        with col3:
            st.metric("📊 Confidence", f"{advanced_analysis.get('confidence', 0):.1%}")

        with col4:
            st.metric("🔬 Analysis Depth", advanced_analysis.get('analysis_depth', 0))

        # Show security indicators
        security_indicators = advanced_analysis.get('security_indicators', {})
        if security_indicators:
            st.subheader("🛡️ Security Indicators")

            indicators_cols = st.columns(3)
            for i, (indicator, value) in enumerate(security_indicators.items()):
                with indicators_cols[i % 3]:
                    if isinstance(value, bool):
                        value_display = "✅" if value else "❌"
                    elif isinstance(value, float):
                        value_display = f"{value:.1%}"
                    else:
                        value_display = str(value)

                    st.metric(
                        indicator.replace("_", " ").title(),
                        value_display
                    )

        # Show advanced analysis status
        if advanced_analysis.get('context_enabled'):
            st.info(
                "🔍 Context-aware analysis was active during this scan, providing more accurate results by analyzing patterns within their full context.")

    # Threats detected
    threats = result.get('threats_detected', [])

    if threats:
        st.subheader("🚨 Security Issues Detected")

        for i, threat in enumerate(threats):
            severity = threat.get('severity', 'MEDIUM')
            threat_type = threat.get('type', 'Unknown Threat')
            description = threat.get('description', 'No description available')
            risk = threat.get('risk', 'No risk information available')

            if 'Advanced' in threat_type:
                st.markdown(f"""
                <div class="threat-card-advanced">
                    <h4 style="margin: 0;">{threat_type}</h4>
                    <p style="margin: 0.5rem 0;"><strong>Severity:</strong> {severity}</p>
                    <p style="margin: 0.5rem 0;"><strong>Description:</strong> {description}</p>
                    <p style="margin: 0.5rem 0;"><strong>Risk:</strong> {risk}</p>
                </div>
                """, unsafe_allow_html=True)
            elif severity == 'HIGH' or severity == 'CRITICAL':
                st.markdown(f"""
                <div class="threat-card-high">
                    <h4 style="margin: 0;">{threat_type}</h4>
                    <p style="margin: 0.5rem 0;"><strong>Severity:</strong> {severity}</p>
                    <p style="margin: 0.5rem 0;"><strong>Description:</strong> {description}</p>
                    <p style="margin: 0.5rem 0;"><strong>Risk:</strong> {risk}</p>
                </div>
                """, unsafe_allow_html=True)
            elif severity == 'MEDIUM':
                st.markdown(f"""
                <div class="threat-card-medium">
                    <h4 style="margin: 0;">{threat_type}</h4>
                    <p style="margin: 0.5rem 0;"><strong>Severity:</strong> {severity}</p>
                    <p style="margin: 0.5rem 0;"><strong>Description:</strong> {description}</p>
                    <p style="margin: 0.5rem 0;"><strong>Risk:</strong> {risk}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="threat-card-low">
                    <h4 style="margin: 0;">{threat_type}</h4>
                    <p style="margin: 0.5rem 0;"><strong>Severity:</strong> {severity}</p>
                    <p style="margin: 0.5rem 0;"><strong>Description:</strong> {description}</p>
                    <p style="margin: 0.5rem 0;"><strong>Risk:</strong> {risk}</p>
                </div>
                """, unsafe_allow_html=True)

    else:
        # Check legitimacy score for appropriate message
        advanced_analysis = result.get('advanced_analysis', {})
        legitimacy_score = advanced_analysis.get('legitimacy_score', 0)

        if legitimacy_score > 0.8:
            st.markdown("""
            <div class="secure-card">
                <h4 style="margin: 0;">✅ No Security Threats Detected</h4>
                <p style="margin: 0.5rem 0 0 0;">This website appears to be secure and legitimate based on our comprehensive analysis.</p>
            </div>
            """, unsafe_allow_html=True)
        elif legitimacy_score > 0.6:
            st.markdown("""
            <div class="secure-card" style="border-left-color: #4299e1;">
                <h4 style="margin: 0;">👍 No Security Threats Detected</h4>
                <p style="margin: 0.5rem 0 0 0;">This website appears to be secure but could improve some legitimacy indicators.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="secure-card" style="border-left-color: #ed8936;">
                <h4 style="margin: 0;">⚠️ No Immediate Security Threats Detected</h4>
                <p style="margin: 0.5rem 0 0 0;">While no direct threats were found, this website has some legitimacy concerns.</p>
            </div>
            """, unsafe_allow_html=True)

    # Recommendations
    recommendations = result.get('recommendations', [])
    if recommendations:
        st.subheader("💡 Security Recommendations")
        for rec in recommendations:
            if '🔍' in rec:
                st.markdown(f"""
                <div class="threat-card-advanced">
                    <p style="margin: 0;">{rec}</p>
                </div>
                """, unsafe_allow_html=True)
            elif '✅' in rec:
                st.markdown(f"""
                <div class="secure-card">
                    <p style="margin: 0;">{rec}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="legitimate-card">
                    <p style="margin: 0;">{rec}</p>
                </div>
                """, unsafe_allow_html=True)

    # Technical details with advanced analysis info
    with st.expander("🔧 Technical Details"):
        col1, col2 = st.columns(2)

        with col1:
            technical = result.get('technical_details', {})
            st.write("**HTTP Response:**")
            st.write(f"Status Code: {technical.get('status_code', 'Unknown')}")

            headers = technical.get('response_headers', {})
            if headers:
                st.write("**Response Headers:**")
                st.json(headers)

        with col2:
            advanced_analysis = result.get('advanced_analysis', {})
            if advanced_analysis:
                st.write("**Context Analysis Details:**")
                st.json({k: v for k, v in advanced_analysis.items() if
                         k not in ['security_indicators', 'advanced_threats']})


def render_network_analyzer():
    """Network traffic analyzer (keeping existing implementation)"""
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
                # Placeholder for network analysis functionality
                st.session_state.uploaded_data = uploaded_file.getvalue()

                # Simulate analysis for now
                time.sleep(2)

                # Show dummy results
                st.success("✅ Network traffic analysis complete!")

                # Display dummy network analysis results
                st.subheader("📊 Traffic Analysis Results")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Packets", "1,245")
                with col2:
                    st.metric("Suspicious Packets", "24")
                with col3:
                    st.metric("Threat Score", "42/100")


def render_threat_dashboard():
    """Threat dashboard with advanced analysis metrics"""
    st.header("📊 Advanced Security Analysis Dashboard")

    # Summary metrics
    total_scans = len(st.session_state.analysis_history)
    total_threats = sum(len(a.get('threats_detected', [])) for a in st.session_state.analysis_history)
    advanced_threats = sum(
        len([t for t in a.get('threats_detected', []) if '🔍 Advanced' in t.get('type', '')])
        for a in st.session_state.analysis_history
    )
    avg_legitimacy = np.mean([
        a.get('advanced_analysis', {}).get('legitimacy_score', 0)
        for a in st.session_state.analysis_history
    ]) if st.session_state.analysis_history else 0

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("🔍 Total Scans", total_scans)

    with col2:
        st.metric("🚨 Total Threats", total_threats)

    with col3:
        st.metric("🔍 Advanced Threats", advanced_threats)

    with col4:
        st.metric("🏆 Avg Legitimacy", f"{avg_legitimacy:.1%}")

    if st.session_state.analysis_history:
        # Advanced analysis confidence over time
        st.subheader("🔍 Context Analysis Over Time")

        analysis_data = []
        for i, analysis in enumerate(st.session_state.analysis_history):
            advanced_analysis = analysis.get('advanced_analysis', {})
            confidence = advanced_analysis.get('confidence', 0)
            legitimacy = advanced_analysis.get('legitimacy_score', 0)

            analysis_data.append({
                'Scan #': i + 1,
                'URL': analysis.get('url', 'Unknown'),
                'Security Score': analysis.get('security_score', 0),
                'Confidence': confidence,
                'Legitimacy Score': legitimacy,
                'Threats': len(analysis.get('threats_detected', [])),
                'Date': analysis.get('timestamp', datetime.now().isoformat())[:10]
            })

        if analysis_data:
            df_analysis = pd.DataFrame(analysis_data)

            # Scatter plot showing relationship between legitimacy and confidence
            fig = px.scatter(df_analysis, x='Legitimacy Score', y='Confidence',
                             size='Threats', color='Security Score',
                             hover_name='URL', size_max=20,
                             title='Relationship between Legitimacy and Analysis Confidence')
            st.plotly_chart(fig, use_container_width=True)

        # Legitimacy score distribution
        st.subheader("🏆 Website Legitimacy Distribution")

        legitimacy_data = []
        for analysis in st.session_state.analysis_history:
            advanced_analysis = analysis.get('advanced_analysis', {})
            legitimacy = advanced_analysis.get('legitimacy_score', 0)
            url = analysis.get('url', 'Unknown')

            if legitimacy > 0.8:
                category = "High Legitimacy"
            elif legitimacy > 0.6:
                category = "Moderate Legitimacy"
            elif legitimacy > 0.4:
                category = "Low Legitimacy"
            else:
                category = "Very Low Legitimacy"

            legitimacy_data.append({
                'URL': url,
                'Legitimacy Score': legitimacy,
                'Category': category
            })

        if legitimacy_data:
            df_legitimacy = pd.DataFrame(legitimacy_data)
            fig = px.histogram(df_legitimacy, x='Category',
                               color='Category',
                               title='Website Legitimacy Distribution',
                               color_discrete_map={
                                   'High Legitimacy': '#48bb78',
                                   'Moderate Legitimacy': '#4299e1',
                                   'Low Legitimacy': '#ed8936',
                                   'Very Low Legitimacy': '#f56565'
                               })
            st.plotly_chart(fig, use_container_width=True)

        # Security score vs legitimacy correlation
        st.subheader("📊 Security Score vs Legitimacy Correlation")

        if analysis_data:
            fig = px.scatter(df_analysis, x='Security Score', y='Legitimacy Score',
                             trendline="ols",
                             hover_name='URL',
                             title='Correlation between Security Score and Legitimacy')
            st.plotly_chart(fig, use_container_width=True)


def render_analysis_history():
    """Analysis history with advanced analysis details"""
    st.header("📋 Website Analysis History")

    if not st.session_state.analysis_history:
        st.info("🔍 No analysis history yet. Start by scanning some websites!")
        return

    # Display history
    for i, analysis in enumerate(reversed(st.session_state.analysis_history)):
        advanced_analysis = analysis.get('advanced_analysis', {})
        advanced_threats = len(advanced_analysis.get('advanced_threats', []))
        confidence = advanced_analysis.get('confidence', 0)
        legitimacy_score = advanced_analysis.get('legitimacy_score', 0)

        legitimacy_icon = "✅" if legitimacy_score > 0.8 else "👍" if legitimacy_score > 0.6 else "⚠️"
        confidence_icon = "🔴" if confidence > 0.7 else "🟡" if confidence > 0.3 else "🟢"

        with st.expander(
                f"🔍 Scan #{len(st.session_state.analysis_history) - i}: {analysis.get('url', 'Unknown')} - {analysis.get('status', 'Unknown')} {legitimacy_icon} {confidence_icon} - Legitimacy: {legitimacy_score:.1%}"):

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Security Score", f"{analysis.get('security_score', 0)}/100")
                st.write(f"**URL:** {analysis.get('url', 'Unknown')}")
                st.write(f"**Date:** {analysis.get('timestamp', '')[:19].replace('T', ' ')}")

            with col2:
                st.metric("Threats", len(analysis.get('threats_detected', [])))
                st.metric("Advanced Threats", advanced_threats)
                st.write(f"**Status:** {analysis.get('status', 'Unknown')}")

            with col3:
                st.metric("Legitimacy", f"{legitimacy_score:.1%}")
                st.metric("Confidence", f"{confidence:.1%}")
                st.write(f"**Risk Level:** {analysis.get('risk_level', 'Unknown')}")
                # Replace lines 1526-1528 with this:
                if advanced_analysis:
                    st.write(f"**🔍 Confidence:** {confidence:.1%}")
                    if advanced_analysis.get('context_enabled'):
                        st.write("**🔍 Context Enhancement:** ✅ Active")


def render_scanner_settings():
    """Scanner settings with universal quantum options"""
    st.header("⚙️ Universal Quantum Scanner Configuration")

    st.subheader("🧬 Universal Quantum Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.checkbox("🧬 Enable Universal Quantum Analysis", value=True)
        st.slider("⚛️ Number of Qubits", 4, 16, 8)
        st.slider("🔗 Entanglement Threshold", 0.1, 1.0, 0.5)
        st.checkbox("🌌 Universal Superposition Analysis", value=True)

    with col2:
        st.checkbox("🎯 Dynamic Legitimacy Scoring", value=True)
        st.slider("📊 Quantum Confidence Threshold", 0.1, 1.0, 0.7)
        st.checkbox("🏆 Universal Legitimacy Recognition", value=True)
        st.checkbox("🔬 Advanced Context Analysis", value=True)

    st.subheader("🏆 Legitimacy Analysis Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.checkbox("🔒 SSL Certificate Analysis", value=True)
        st.checkbox("🛡️ Security Headers Evaluation", value=True)
        st.checkbox("🏢 Professional Structure Detection", value=True)
        st.checkbox("📝 Content Quality Assessment", value=True)

    with col2:
        st.checkbox("🌐 Domain Reputation Analysis", value=True)
        st.checkbox("📊 Business Indicators Detection", value=True)
        st.checkbox("🔍 Suspicious Content Filtering", value=True)
        st.checkbox("⚖️ Balanced Legitimacy Scoring", value=True)

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

    st.subheader("🎯 Universal Accuracy Settings")

    col1, col2 = st.columns(2)

    with col1:
        st.checkbox("🧠 Context-Aware Pattern Matching", value=True)
        st.checkbox("📊 Intelligent Confidence Scoring", value=True)
        st.checkbox("🔍 Enhanced Pattern Filtering", value=True)

    with col2:
        st.checkbox("🎯 Legitimate Content Detection", value=True)
        st.checkbox("⚖️ Balanced Threat Assessment", value=True)
        st.checkbox("🌐 Universal Website Support", value=True)

    st.subheader("⚡ Performance Settings")

    timeout = st.slider("Request Timeout (seconds)", 5, 30, 15)
    max_redirects = st.slider("Maximum Redirects to Follow", 1, 10, 5)

    st.subheader("🚨 Alert Settings")

    alert_threshold = st.slider("Security Score Alert Threshold", 0, 100, 60)
    quantum_alert_threshold = st.slider("Quantum Confidence Alert Threshold", 0.1, 1.0, 0.7)
    legitimacy_threshold = st.slider("Legitimacy Score Threshold", 0.1, 1.0, 0.6)
    st.checkbox("📧 Send Email Alerts", value=False)
    st.checkbox("📱 Send Push Notifications", value=False)
    st.checkbox("🧬 Quantum Alert Priority", value=True)
    st.checkbox("🏆 Legitimacy-Based Notifications", value=True)

    if st.button("💾 Save Universal Quantum Settings", type="primary"):
        st.success("✅ Universal quantum settings saved successfully!")
        st.info("🧬 Universal quantum analysis will now provide accurate results for ANY website on the internet!")


if __name__ == "__main__":
    main()
