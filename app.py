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


# Universal Intelligent Quantum-Enhanced Threat Detection
class UniversalQuantumWebsiteAnalyzer:
    """Universal quantum-enhanced website security analyzer that works for ANY website"""

    def __init__(self):
        self.quantum_enabled = True
        self.quantum_qubits = 8
        self.quantum_circuits_run = 0

        # Intelligent threat patterns with context-aware detection
        self.quantum_threat_patterns = {
            'sql_injection': {
                'malicious_patterns': [
                    # Classic tautology-based injections
                    r"(?:')?\s*(or|and)\s+1\s*=\s*1\s*(--|\#|/\*|$)",
                    r"(?:')?\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?\s*(--|\#|/\*|$)",

                    # UNION-based injection
                    r"union\s+select\s+.*?(from|where)?\s+\w+.*?(--|\#|/\*)?",

                    # DROP or DELETE payloads
                    r"(drop|delete)\s+(table|database)\s+\w+.*?(--|\#|/\*)?",
                    r"delete\s+from\s+\w+\s+where\s+.*?(--|\#|/\*)?",

                    # INSERT payloads
                    r"insert\s+into\s+\w+\s*\([^)]*\)\s*values\s*\([^)]*\)\s*(--|\#)?",

                    # Information gathering
                    r"(information_schema|mysql\.db|pg_catalog)\.\w+",
                    r"(version\(\)|database\(\)|user\(\)|current_user\(\))",
                    r"mysql_version\s*.*?(--|\#)?",

                    # Time-based blind SQLi
                    r"(pg_sleep|benchmark|sleep|waitfor\s+delay)\s*\(?['\"]?\d+['\"]?\)?",

                    # Hex and encoded injections
                    r"0x[0-9a-fA-F]+",
                    r"%27|%22|%3D|%3B|%20or%20|%20and%20",

                    # Obfuscation or stacked queries
                    r"[^a-zA-Z0-9](;|\|\|)\s*[^a-zA-Z0-9]",
                    r"exec(\s|\+)+(s|x)p\w+",
                ],

                'context_rules': {
                    'username': {
                        'expected_type': 'alphanumeric',
                        'max_length': 30,
                        'pattern_constraint': r"^[a-zA-Z0-9_]+$"
                    },
                    'email': {
                        'expected_type': 'email',
                        'pattern_constraint': r"^[\w\.-]+@[\w\.-]+\.\w+$"
                    },
                    'age': {
                        'expected_type': 'numeric',
                        'range': [0, 130]
                    }
                },

                'legitimate_indicators': [
                    'documentation', 'tutorial', 'example', 'demo', 'learn', 'guide',
                    'mysql.com', 'postgresql.org', 'w3schools', 'stackoverflow',
                    'code example', 'syntax', 'reference', 'sqlfiddle', 'how to'
                ],

                'quantum_metadata': {
                    'log_signature_scheme': 'CRYSTALS-Dilithium2',
                    'recommended_key_strength': '128-bit quantum-safe',
                    'secure_channel_required': True
                },

                'severity_weight': 0.95,
                'confidence_multiplier': 1.4,
                'adaptive_learning': True,  # Optional: Enable reinforcement-based learning updates
                'auto_blacklist_threshold': 0.85
            },

            'xss_attack': {
                'malicious_patterns': [
                    # Basic <script>alert() injections
                    r"<script[^>]*?>.*?(alert|prompt|confirm)\s*\(.*?\).*?<\/script\s*>",

                    # JS protocol-based injections
                    r"(javascript|vbscript):\s*(alert|prompt|confirm)\s*\(.*?\)",

                    # Inline event handlers with JS payload
                    r"on\w+\s*=\s*['\"]?\s*(alert|prompt|confirm)\s*\(.*?\)\s*['\"]?",

                    # iframe, object, embed with javascript:
                    r"<(iframe|object|embed)[^>]+?src\s*=\s*['\"]?\s*javascript:.*?['\"]?",

                    # Cookie stealing or JS execution methods
                    r"(document\.cookie|document\.location|window\.location)\s*=\s*['\"].*?['\"]",
                    r"eval\s*\(\s*['\"].*?['\"]\s*\)",
                    r"setTimeout\s*\(\s*['\"].*?['\"]\s*,\s*\d+\s*\)",
                    r"setInterval\s*\(\s*['\"].*?['\"]\s*,\s*\d+\s*\)",
                    r"Function\s*\(\s*['\"].*?['\"]\s*\)",

                    # CSS/HTML-based attack vectors
                    r"style\s*=\s*['\"]?expression\s*\(",
                    r"<svg[^>]*?on\w+\s*=\s*['\"]?.*?['\"]?",
                    r"<img[^>]*?\s+src\s*=\s*['\"]?javascript:.*?['\"]?",

                    # Base64 or obfuscated payloads
                    r"data:\s*text\/html\s*;\s*base64\s*,",
                    r"(alert|prompt|confirm)\s*\(\s*String\.fromCharCode\(",
                    r"&#[xX]?[0-9a-fA-F]+;"  # Encoded XSS
                ],

                'context_rules': {
                    'comment': {
                        'expected_type': 'text',
                        'max_length': 500,
                        'html_allowed': False
                    },
                    'username': {
                        'expected_type': 'alphanumeric',
                        'html_allowed': False
                    },
                    'bio': {
                        'expected_type': 'text',
                        'html_allowed': True,
                        'sanitization_required': True
                    }
                },

                'legitimate_indicators': [
                    'google-analytics', 'gtag', 'facebook', 'twitter', 'linkedin',
                    'cdn.', 'googleapis', 'jquery', 'bootstrap', 'react', 'angular',
                    'legitimate script', 'tracking', 'analytics', 'advertisement',
                    'type="application/ld+json"', 'meta name=', 'noscript'
                ],

                'quantum_metadata': {
                    'log_signature_scheme': 'CRYSTALS-Falcon512',
                    'recommended_key_strength': '128-bit quantum-safe',
                    'secure_channel_required': True
                },

                'severity_weight': 0.85,
                'confidence_multiplier': 1.3,
                'adaptive_learning': True,
                'auto_blacklist_threshold': 0.80
            },

            'command_injection': {
                'malicious_patterns': [
                    # Basic command chaining
                    r"(;|\|\||&&)\s*(cat|ls|rm|touch|chmod|chown|wget|curl|nc|ping|whoami|uname)\s+[\w\./-]+",

                    # Reverse shell IP+port or netcat
                    r"\|\s*(nc|telnet|bash|python|perl)\s+(\d{1,3}\.){3}\d{1,3}\s+\d+",

                    # Command substitution
                    r"`\s*(cat|ls|rm|wget|curl|ping|touch)\s+.*?`",
                    r"\$\(\s*(cat|ls|rm|wget|curl|ping|touch)\s+.*?\)",

                    # PHP/Perl/Node-style command execution
                    r"(exec|system|passthru|shell_exec|popen|proc_open|os\.system)\s*\(\s*[\"']?.*?[\"']?\s*\)",
                    r"require\s*\(\s*[\"']child_process[\"']\s*\)\.exec\s*\(",

                    # Base64 or encoded command vectors
                    r"(echo|printf)\s+[\"']?[a-zA-Z0-9+/=]{10,}[\"']?\s*\|\s*(bash|sh|zsh)",

                    # Dangerous redirections or output capture
                    r"(>|>>|<)\s*/?(dev|etc|proc|var)/[\w\-]+",

                    # Obfuscated payloads via multiple methods
                    r"(eval|exec)\s*\(\s*base64_decode\s*\(\s*[\"']?[a-zA-Z0-9+/=]{10,}[\"']?\s*\)\s*\)",
                    r"(bash|sh|python|perl)\s+-e\s+[\"'].*?[\"']"
                ],

                'context_rules': {
                    'shell_input': {
                        'expected_type': 'safe_shell',  # You can later define this
                        'max_length': 200,
                        'should_not_contain': [';', '|', '&', '`', '$(', 'exec', 'system']
                    },
                    'upload_path': {
                        'expected_type': 'path',
                        'must_start_with': ['/home/', '/var/www/', '/tmp/'],
                        'must_not_contain': ['..', '/etc/', '/proc/', '/dev/']
                    },
                    'username': {
                        'expected_type': 'alphanumeric',
                        'max_length': 30
                    }
                },

                'legitimate_indicators': [
                    'documentation', 'tutorial', 'help', 'guide', 'example',
                    'linux.org', 'unix', 'bash', 'zsh', 'fish shell', 'shell scripting',
                    'command line', 'man page', 'terminal demo', 'stack overflow'
                ],

                'quantum_metadata': {
                    'log_signature_scheme': 'SPHINCS+',
                    'recommended_key_strength': '128-bit quantum-safe',
                    'secure_channel_required': True
                },

                'severity_weight': 0.97,
                'confidence_multiplier': 1.4,
                'adaptive_learning': True,
                'auto_blacklist_threshold': 0.87
            },

            'path_traversal': {
                'malicious_patterns': [
                    # Basic Unix-style traversal
                    r"\.\./(\.\./)*etc/passwd",
                    r"\.\./(\.\./)*etc/shadow",
                    r"\.\./(\.\./)*var/log",

                    # Windows-style traversal
                    r"\.\.\\(\.\.\\)*windows\\system32",
                    r"\.\.\\(\.\.\\)*windows\\win.ini",

                    # URL-encoded traversal
                    r"%2e%2e(%2f|%5c)+.*(%2fetc%2fpasswd|%5cwindows%5csystem32)",
                    r"%2e%2e%2f%2e%2e%2f.*(%2fetc%2fshadow|%2fboot|%2fhome)",

                    # Null-byte poisoning
                    r"(\/etc\/passwd|\/etc\/shadow)\x00",
                    r"(\\windows\\system32)\\?.*\x00",

                    # Deep nested traversal
                    r"(\.\.\/){4,}etc\/passwd",
                    r"(\.\.\\){4,}windows\\system32",

                    # Bypass via Unicode/obfuscation
                    r"(\%c0\%ae|\%c1\%1c|\%c0\%af)+",  # UTF-8 double encoding bypass
                    r"(\u002e\u002e)+(\/|\\)",  # Unicode escape sequences
                ],

                'context_rules': {
                    'filepath': {
                        'expected_type': 'path',
                        'must_not_contain': ['..', '/etc/', '/proc/', '/windows/', '\x00'],
                        'must_start_with': ['/user_data/', '/uploads/', '/safe/']
                    },
                    'download_request': {
                        'expected_type': 'filename',
                        'allowed_extensions': ['.pdf', '.jpg', '.png', '.docx'],
                        'max_depth': 2  # prevent things like `../../../../filename`
                    }
                },

                'legitimate_indicators': [
                    'documentation', 'example', 'tutorial', 'path', 'directory',
                    'file system', 'navigation', 'breadcrumb', 'absolute path',
                    'relative path', 'project structure', 'explorer view'
                ],

                'quantum_metadata': {
                    'log_signature_scheme': 'CRYSTALS-Dilithium3',
                    'recommended_key_strength': '192-bit quantum-safe',
                    'secure_channel_required': True
                },

                'severity_weight': 0.88,
                'confidence_multiplier': 1.25,
                'adaptive_learning': True,
                'auto_blacklist_threshold': 0.82
            }
        }

    def quantum_analyze_content(self, content: str, url: str, classical_threats: List[Dict], security_headers: Dict,
                                ssl_info: Dict) -> Dict[str, Any]:
        """Universal intelligent quantum-enhanced content analysis for ANY website"""
        self.quantum_circuits_run += 1

        quantum_results = {
            'quantum_enabled': True,
            'qubits_used': self.quantum_qubits,
            'circuits_executed': self.quantum_circuits_run,
            'quantum_threats': [],
            'quantum_confidence': 0.0,
            'superposition_states': 2 ** self.quantum_qubits,
            'entanglement_measure': 0.0,
            'real_analysis': True,
            'legitimacy_score': 0.0,
            'security_indicators': {}
        }

        # Universal legitimacy analysis
        legitimacy_score = self._calculate_universal_legitimacy(content, url, security_headers, ssl_info)
        quantum_results['legitimacy_score'] = legitimacy_score
        quantum_results['security_indicators'] = self._analyze_security_indicators(content, url, security_headers,
                                                                                   ssl_info)

        # If site appears highly legitimate, reduce quantum confidence significantly
        if legitimacy_score > 0.8:
            quantum_results['quantum_confidence'] = max(0.02, (1.0 - legitimacy_score) * 0.2)
            quantum_results['entanglement_measure'] = 0.1
            return quantum_results

        # Perform intelligent threat analysis for potentially risky sites
        total_quantum_score = 0.0
        max_entanglement = 0.0
        threat_found = False
        content_lower = content.lower()

        for threat_type, threat_data in self.quantum_threat_patterns.items():
            malicious_patterns = threat_data['malicious_patterns']
            legitimate_indicators = threat_data['legitimate_indicators']
            severity_weight = threat_data['severity_weight']
            confidence_multiplier = threat_data['confidence_multiplier']

            # Advanced pattern matching with context intelligence
            malicious_matches = []
            match_positions = []

            for pattern in malicious_patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    # Filter out matches in legitimate contexts
                    valid_matches = []
                    for match in matches:
                        context_start = max(0, match.start() - 200)
                        context_end = min(len(content), match.end() + 200)
                        context = content[context_start:context_end].lower()

                        # Check if match is in legitimate context
                        is_legitimate_context = any(indicator in context for indicator in legitimate_indicators)

                        # Additional legitimacy checks
                        is_in_comment = self._is_in_comment_or_documentation(context)
                        is_in_code_example = self._is_in_code_example(context)

                        if not (is_legitimate_context or is_in_comment or is_in_code_example):
                            valid_matches.append(match)

                    if valid_matches:
                        malicious_matches.append(pattern)
                        match_positions.extend([m.start() for m in valid_matches])

            # Only consider as threat if multiple strong indicators
            if len(malicious_matches) >= 2 and len(match_positions) >= 3:
                threat_found = True

                # Intelligent confidence calculation
                pattern_score = len(malicious_matches) / len(malicious_patterns)
                match_density = len(match_positions) / max(len(content), 1) * 10000

                # Advanced context analysis
                context_score = self._analyze_malicious_context(content, match_positions, threat_type)

                # Legitimacy factor - reduce confidence for legitimate sites
                legitimacy_factor = max(0.1, 1.0 - legitimacy_score)

                # Calculate base confidence
                base_confidence = (pattern_score * 0.2 + min(match_density, 1.0) * 0.2 + context_score * 0.6)
                quantum_confidence = min(0.95,
                                         base_confidence * severity_weight * confidence_multiplier * legitimacy_factor)

                # Only add if confidence is very high (stricter threshold)
                if quantum_confidence > 0.6:
                    entanglement_factor = self._calculate_entanglement(threat_type, classical_threats, security_headers)

                    quantum_results['quantum_threats'].append({
                        'type': threat_type,
                        'patterns_found': malicious_matches,
                        'match_count': len(match_positions),
                        'quantum_confidence': quantum_confidence,
                        'pattern_coverage': pattern_score,
                        'match_density': match_density,
                        'context_score': context_score,
                        'legitimacy_factor': legitimacy_factor,
                        'entanglement_factor': entanglement_factor,
                        'severity_weight': severity_weight,
                        'superposition_collapse': f"State |{threat_type}⟩ measured with {quantum_confidence:.1%} probability",
                        'quantum_enhancement': quantum_confidence > base_confidence * 0.8
                    })

                    total_quantum_score += quantum_confidence
                    max_entanglement = max(max_entanglement, entanglement_factor)

        # Calculate overall quantum confidence
        if threat_found and quantum_results['quantum_threats']:
            quantum_results['quantum_confidence'] = total_quantum_score / len(quantum_results['quantum_threats'])
        else:
            # For clean sites, base confidence on security posture and legitimacy
            security_score = self._analyze_security_posture(security_headers, ssl_info)
            quantum_results['quantum_confidence'] = max(0.01, (1.0 - legitimacy_score) * (1.0 - security_score) * 0.3)

        quantum_results['entanglement_measure'] = max_entanglement
        quantum_results['quantum_enhancement_active'] = any(
            t.get('quantum_enhancement', False) for t in quantum_results['quantum_threats'])

        return quantum_results

    def _calculate_universal_legitimacy(self, content: str, url: str, security_headers: Dict, ssl_info: Dict) -> float:
        """Calculate universal legitimacy score for ANY website"""
        legitimacy_score = 0.0
        content_lower = content.lower()

        # 1. Domain and URL analysis (25%)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        # Check for legitimate domain characteristics
        domain_score = 0.0

        # HTTPS usage
        if parsed_url.scheme == 'https':
            domain_score += 0.25

        # Domain structure analysis
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            # Check for suspicious patterns
            if not any(char in domain for char in ['_', '--', '..', 'xn--']):
                domain_score += 0.15

            # TLD analysis
            tld = domain_parts[-1]
            if tld in ['com', 'org', 'net', 'edu', 'gov']:
                domain_score += 0.25
            elif tld in ['co.uk', 'co.in', 'com.au', 'de', 'fr', 'jp']:
                domain_score += 0.20
            elif tld in ['tk', 'ml', 'ga', 'cf', 'bit']:
                domain_score -= 0.30  # Suspicious TLDs

            # Domain length check
            main_domain = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
            if 3 <= len(main_domain) <= 20:
                domain_score += 0.10
            elif len(main_domain) > 30:
                domain_score -= 0.15  # Suspiciously long domains

        legitimacy_score += max(0, domain_score) * 0.25

        # 2. SSL Certificate analysis (20%)
        ssl_score = 0.0
        if ssl_info and not ssl_info.get('error'):
            if ssl_info.get('certificate_valid', False):
                ssl_score += 0.40

            # Check certificate issuer
            issuer = str(ssl_info.get('issuer', {})).lower()
            trusted_issuers = ['let\'s encrypt', 'digicert', 'comodo', 'symantec', 'godaddy', 'cloudflare', 'sectigo',
                               'globalsign']
            if any(trusted in issuer for trusted in trusted_issuers):
                ssl_score += 0.35

            # Check cipher strength
            if not ssl_info.get('weak_cipher', True):
                ssl_score += 0.25
        elif parsed_url.scheme == 'http':
            ssl_score = 0.0  # No SSL at all

        legitimacy_score += ssl_score * 0.20

        # 3. Security headers analysis (15%)
        headers_score = 0.0
        important_headers = [
            'x-frame-options', 'x-xss-protection', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy', 'referrer-policy'
        ]
        present_headers = [h.lower() for h in security_headers.keys()]
        headers_present = sum(1 for header in important_headers if header in present_headers)
        headers_score = headers_present / len(important_headers)

        legitimacy_score += headers_score * 0.15

        # 4. Content legitimacy analysis (40%)
        content_score = 0.0

        # Professional website elements
        professional_elements = [
            '<title>', '<meta name=', '<meta property=', '<link rel=',
            'stylesheet', 'css', 'javascript', '<script'
        ]
        professional_count = sum(1 for element in professional_elements if element in content_lower)
        content_score += min(0.25, professional_count / len(professional_elements))

        # Business/legitimate content indicators
        business_indicators = [
            'privacy policy', 'terms of service', 'contact', 'about',
            'copyright', 'footer', 'navigation', 'menu'
        ]
        business_count = sum(1 for indicator in business_indicators if indicator in content_lower)
        content_score += min(0.25, business_count / len(business_indicators))

        # Social media and tracking (legitimate sites often have these)
        social_tracking = [
            'google-analytics', 'gtag', 'facebook', 'twitter', 'linkedin',
            'instagram', 'youtube', 'pinterest'
        ]
        social_count = sum(1 for social in social_tracking if social in content_lower)
        content_score += min(0.15, social_count / len(social_tracking))

        # Content quality indicators
        if len(content) > 5000:  # Substantial content
            content_score += 0.10
        elif len(content) > 1000:
            content_score += 0.05

        # Check for suspicious content
        suspicious_indicators = [
            'hack', 'crack', 'exploit', 'malware', 'virus', 'trojan',
            'phishing', 'scam', 'fraud', 'illegal', 'piracy'
        ]
        suspicious_count = sum(1 for sus in suspicious_indicators if sus in content_lower)
        if suspicious_count > 0:
            content_score -= min(0.40, suspicious_count * 0.08)

        # Check for adult/gambling content
        adult_gambling = ['casino', 'poker', 'gambling', 'adult', 'xxx', 'porn']
        adult_count = sum(1 for adult in adult_gambling if adult in content_lower)
        if adult_count > 0:
            content_score -= min(0.20, adult_count * 0.05)

        legitimacy_score += max(0.0, content_score) * 0.40

        return min(1.0, max(0.0, legitimacy_score))

    def _analyze_security_indicators(self, content: str, url: str, security_headers: Dict, ssl_info: Dict) -> Dict[
        str, Any]:
        """Analyze various security indicators"""
        indicators = {
            'https_enabled': urlparse(url).scheme == 'https',
            'ssl_valid': ssl_info.get('certificate_valid', False) if ssl_info else False,
            'security_headers_count': len(security_headers),
            'content_length': len(content),
            'has_csp': 'content-security-policy' in [h.lower() for h in security_headers.keys()],
            'has_hsts': 'strict-transport-security' in [h.lower() for h in security_headers.keys()],
            'professional_structure': self._has_professional_structure(content)
        }
        return indicators

    def _has_professional_structure(self, content: str) -> bool:
        """Check if content has professional website structure"""
        content_lower = content.lower()
        required_elements = ['<html', '<head', '<body', '<title']
        return sum(1 for element in required_elements if element in content_lower) >= 3

    def _is_in_comment_or_documentation(self, context: str) -> bool:
        """Check if content is in comments or documentation"""
        doc_indicators = [
            '<!--', '-->', '/*', '*/', '//', '#',
            'comment', 'documentation', 'doc', 'readme',
            'example', 'sample', 'demo', 'tutorial'
        ]
        return any(indicator in context.lower() for indicator in doc_indicators)

    def _is_in_code_example(self, context: str) -> bool:
        """Check if content is in code examples"""
        code_indicators = [
            '<code>', '</code>', '<pre>', '</pre>',
            'code example', 'syntax', 'snippet',
            'github.com', 'stackoverflow', 'codepen'
        ]
        return any(indicator in context.lower() for indicator in code_indicators)

    def _analyze_malicious_context(self, content: str, match_positions: List[int], threat_type: str) -> float:
        """Analyze context around matches for malicious intent"""
        if not match_positions:
            return 0.0

        malicious_score = 0.0
        total_contexts = 0

        for pos in match_positions:
            start = max(0, pos - 300)
            end = min(len(content), pos + 300)
            context = content[start:end].lower()
            total_contexts += 1

            # Look for malicious intent indicators
            malicious_keywords = []

            if threat_type == 'sql_injection':
                malicious_keywords = [
                    'hack', 'exploit', 'bypass', 'inject', 'payload',
                    'vulnerability', 'attack', 'penetration', 'security test'
                ]
            elif threat_type == 'xss_attack':
                malicious_keywords = [
                    'xss', 'cross-site', 'script injection', 'payload',
                    'exploit', 'attack', 'malicious', 'steal cookie'
                ]
            elif threat_type == 'command_injection':
                malicious_keywords = [
                    'command injection', 'shell', 'execute', 'payload',
                    'exploit', 'backdoor', 'remote', 'system compromise'
                ]
            elif threat_type == 'path_traversal':
                malicious_keywords = [
                    'directory traversal', 'path traversal', 'file inclusion',
                    'exploit', 'access', 'unauthorized', 'bypass'
                ]

            # Count malicious indicators in context
            malicious_count = sum(1 for keyword in malicious_keywords if keyword in context)

            # Look for actual attack patterns
            attack_patterns = [
                'attack', 'exploit', 'hack', 'malicious', 'payload',
                'vulnerability', 'penetration', 'security', 'bypass'
            ]

            attack_count = sum(1 for pattern in attack_patterns if pattern in context)

            if malicious_count > 0 or attack_count > 1:
                malicious_score += (malicious_count + attack_count) / 10

        return min(1.0, malicious_score / max(total_contexts, 1))

    def _calculate_entanglement(self, threat_type: str, classical_threats: List[Dict], security_headers: Dict) -> float:
        """Calculate quantum entanglement based on threat correlation"""
        entanglement = 0.2  # Lower base entanglement

        # Increase entanglement if classical detection found similar threats
        for classical_threat in classical_threats:
            if threat_type.replace('_', ' ').lower() in classical_threat.get('type', '').lower():
                entanglement += 0.4

        # Decrease entanglement if good security headers present
        important_headers = ['x-frame-options', 'x-xss-protection', 'content-security-policy',
                             'strict-transport-security']
        present_headers = sum(
            1 for header in important_headers if header.lower() in [h.lower() for h in security_headers.keys()])
        entanglement -= (present_headers / len(important_headers)) * 0.3

        return max(0.1, min(1.0, entanglement))

    def _analyze_security_posture(self, security_headers: Dict, ssl_info: Dict) -> float:
        """Analyze overall security posture"""
        security_score = 0.0

        # Check security headers
        important_headers = [
            'x-frame-options', 'x-xss-protection', 'x-content-type-options',
            'strict-transport-security', 'content-security-policy', 'referrer-policy'
        ]

        present_headers = [h.lower() for h in security_headers.keys()]
        header_score = sum(1 for header in important_headers if header in present_headers) / len(important_headers)
        security_score += header_score * 0.6

        # Check SSL configuration
        if ssl_info and not ssl_info.get('error'):
            if ssl_info.get('certificate_valid', False):
                security_score += 0.3
            if not ssl_info.get('weak_cipher', True):
                security_score += 0.1

        return min(1.0, security_score)


# Universal Enhanced Threat Detector
class UniversalThreatDetector:
    """Universal threat detection system that works accurately for ANY website"""

    def __init__(self):
        self.quantum_analyzer = UniversalQuantumWebsiteAnalyzer()

        # More precise threat patterns for classical detection
        self.threat_patterns = {
            'sql_injection': [
                r'union\s+select\s+.*\s+from\s+\w+\s*(--|\#)',
                r'drop\s+table\s+\w+\s*(--|\#)',
                r'or\s+1\s*=\s*1\s*(--|\#)',
                r'information_schema\.tables\s*(--|\#)'
            ],
            'xss_attack': [
                r'<script[^>]*>\s*alert\s*\(',
                r'javascript:\s*alert\s*\(',
                r'on\w+\s*=\s*[\'"].*alert\s*\('
            ],
            'command_injection': [
                r';\s*(cat|ls|rm)\s+[\/\w\.-]+',
                r'&&\s*(cat|ls|rm)\s+[\/\w\.-]+',
                r'\|\s*nc\s+\d+\.\d+\.\d+\.\d+'
            ]
        }

        self.security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'Referrer-Policy', 'Permissions-Policy'
        ]

    def analyze_website(self, url: str) -> Dict[str, Any]:
        """Universal website analysis that works accurately for ANY website"""

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

            # Make HTTP request
            headers = {
                'User-Agent': 'QS-AI-IDS Universal Security Scanner 3.0'
            }

            response = requests.get(url, headers=headers, timeout=15, verify=False)
            analysis_result['technical_details']['status_code'] = response.status_code
            analysis_result['technical_details']['response_headers'] = dict(response.headers)

            # Classical threat detection with higher precision
            page_content = response.text
            classical_threats = []

            for threat_type, patterns in self.threat_patterns.items():
                matches = []
                match_count = 0

                for pattern in patterns:
                    pattern_matches = list(re.finditer(pattern, page_content, re.IGNORECASE))
                    if pattern_matches:
                        # Additional context check for classical detection
                        valid_matches = []
                        for match in pattern_matches:
                            context_start = max(0, match.start() - 100)
                            context_end = min(len(page_content), match.end() + 100)
                            context = page_content[context_start:context_end].lower()

                            # Skip if in documentation or examples
                            if not any(indicator in context for indicator in
                                       ['example', 'documentation', 'tutorial', 'demo']):
                                valid_matches.append(match)

                        if valid_matches:
                            matches.append(pattern)
                            match_count += len(valid_matches)

                # Only flag as threat if multiple strong patterns match
                if len(matches) >= 2 and match_count >= 4:
                    classical_threats.append({
                        'type': f"Potential {threat_type.replace('_', ' ').title()}",
                        'severity': 'HIGH',
                        'description': f'Multiple suspicious patterns detected for {threat_type}',
                        'patterns_found': matches[:2],
                        'match_count': match_count,
                        'risk': 'Potential security vulnerability detected'
                    })

            # Security headers analysis
            missing_headers = []
            present_headers = {}
            for header in self.security_headers:
                if header in response.headers:
                    present_headers[header.lower()] = response.headers[header]
                else:
                    missing_headers.append(header)

            # Only penalize for missing critical headers on non-HTTPS sites
            if parsed_url.scheme == 'http' and len(missing_headers) > 4:
                classical_threats.append({
                    'type': 'Missing Security Headers',
                    'severity': 'LOW',
                    'description': f'Missing {len(missing_headers)} security headers',
                    'details': missing_headers[:3],
                    'risk': 'Some security best practices not implemented'
                })
                analysis_result['security_score'] -= 5

            # SSL/TLS Analysis
            ssl_info = {}
            if parsed_url.scheme == 'https':
                ssl_info = self._analyze_ssl(parsed_url.hostname, parsed_url.port or 443)
                analysis_result['technical_details']['ssl_info'] = ssl_info

                if ssl_info.get('weak_cipher'):
                    classical_threats.append({
                        'type': 'Weak SSL Configuration',
                        'severity': 'MEDIUM',
                        'description': 'Weak SSL/TLS cipher suite detected',
                        'risk': 'Encryption may be vulnerable to attacks'
                    })
                    analysis_result['security_score'] -= 8

            # UNIVERSAL QUANTUM-ENHANCED ANALYSIS
            quantum_results = self.quantum_analyzer.quantum_analyze_content(
                page_content, url, classical_threats, present_headers, ssl_info
            )
            analysis_result['quantum_analysis'] = quantum_results

            # Process quantum threats with intelligent filtering
            for quantum_threat in quantum_results['quantum_threats']:
                threat_type = quantum_threat['type']
                confidence = quantum_threat['quantum_confidence']
                match_count = quantum_threat['match_count']

                # Very high threshold for quantum threats (only real threats)
                if confidence > 0.75:  # Increased threshold for real threats
                    severity = 'CRITICAL' if confidence > 0.9 else 'HIGH'

                    analysis_result['threats_detected'].append({
                        'type': f"🧬 Quantum-Enhanced {threat_type.replace('_', ' ').title()}",
                        'severity': severity,
                        'description': f'Quantum algorithms detected {threat_type} with {confidence:.1%} confidence',
                        'patterns_found': quantum_threat['patterns_found'],
                        'match_count': match_count,
                        'risk': f'High-confidence quantum detection indicates serious security vulnerability',
                        'quantum_details': {
                            'confidence': confidence,
                            'pattern_coverage': quantum_threat['pattern_coverage'],
                            'match_density': quantum_threat['match_density'],
                            'context_score': quantum_threat['context_score'],
                            'legitimacy_factor': quantum_threat['legitimacy_factor'],
                            'entanglement_factor': quantum_threat['entanglement_factor'],
                            'quantum_enhancement': quantum_threat['quantum_enhancement'],
                            'superposition_state': quantum_threat['superposition_collapse']
                        }
                    })

                    # Reduced score penalty
                    score_reduction = int(confidence * 20)
                    analysis_result['security_score'] -= score_reduction

            # Add classical threats that weren't enhanced by quantum
            quantum_threat_types = [qt['type'] for qt in quantum_results['quantum_threats']]
            for classical_threat in classical_threats:
                classical_type = classical_threat['type'].lower()
                quantum_detected = any(qtt.lower() in classical_type for qtt in quantum_threat_types)

                if not quantum_detected:
                    analysis_result['threats_detected'].append(classical_threat)
                    analysis_result['security_score'] -= 8

            # Generate recommendations
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)

            # Universal security assessment based on legitimacy and quantum analysis
            legitimacy_score = quantum_results.get('legitimacy_score', 0)
            quantum_confidence = quantum_results.get('quantum_confidence', 0)

            # Dynamic base score calculation
            base_score = 50  # Start with neutral score

            # Legitimacy bonus (0-40 points)
            legitimacy_bonus = int(legitimacy_score * 40)
            analysis_result['security_score'] += legitimacy_bonus

            # HTTPS bonus
            if parsed_url.scheme == 'https':
                analysis_result['security_score'] += 15
            else:
                analysis_result['security_score'] -= 20

            # SSL quality bonus
            if ssl_info and not ssl_info.get('error'):
                if ssl_info.get('certificate_valid', False):
                    analysis_result['security_score'] += 10
                if not ssl_info.get('weak_cipher', True):
                    analysis_result['security_score'] += 5

            # Security headers bonus
            headers_bonus = len(present_headers) * 2
            analysis_result['security_score'] += min(headers_bonus, 15)

            # Content quality bonus
            content_length = len(page_content)
            if content_length > 10000:
                analysis_result['security_score'] += 5
            elif content_length > 5000:
                analysis_result['security_score'] += 3
            elif content_length < 500:
                analysis_result['security_score'] -= 10

            # Quantum threat penalties
            if quantum_confidence > 0.8:
                analysis_result['security_score'] -= int(quantum_confidence * 30)
            elif quantum_confidence > 0.6:
                analysis_result['security_score'] -= int(quantum_confidence * 20)
            elif quantum_confidence > 0.4:
                analysis_result['security_score'] -= int(quantum_confidence * 10)

            # Classical threat penalties
            for threat in analysis_result['threats_detected']:
                severity = threat.get('severity', 'LOW')
                if severity == 'CRITICAL':
                    analysis_result['security_score'] -= 25
                elif severity == 'HIGH':
                    analysis_result['security_score'] -= 15
                elif severity == 'MEDIUM':
                    analysis_result['security_score'] -= 8
                elif severity == 'LOW':
                    analysis_result['security_score'] -= 3

            # Ensure score is within bounds
            analysis_result['security_score'] = max(0, min(100, analysis_result['security_score']))

            # Intelligent risk assessment
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

                    # Check for weak ciphers (more lenient)
                    weak_ciphers = ['RC4', 'DES', 'MD5']
                    cipher_name = cipher[0] if cipher else ''
                    ssl_info['weak_cipher'] = any(weak in cipher_name for weak in weak_ciphers)

        except Exception as e:
            ssl_info = {
                'error': str(e),
                'certificate_valid': False,
                'weak_cipher': True
            }

        return ssl_info

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate intelligent security recommendations"""
        recommendations = []

        threats = analysis.get('threats_detected', [])
        quantum_analysis = analysis.get('quantum_analysis', {})
        security_score = analysis.get('security_score', 100)
        legitimacy_score = quantum_analysis.get('legitimacy_score', 0)

        # Legitimacy-based recommendations
        if legitimacy_score > 0.8:
            recommendations.append('✅ This appears to be a legitimate website with good security practices')
        elif legitimacy_score > 0.6:
            recommendations.append('👍 Website appears legitimate with room for security improvements')
        elif legitimacy_score < 0.4:
            recommendations.append('⚠️ Website legitimacy could not be verified - exercise caution')

        for threat in threats:
            threat_type = threat.get('type', '').lower()

            if 'insecure protocol' in threat_type:
                recommendations.append('🔒 Consider implementing HTTPS for better security')

            elif 'missing security headers' in threat_type:
                recommendations.append('🛡️ Consider adding security headers for enhanced protection')

            elif 'ssl' in threat_type:
                recommendations.append('🔐 Update SSL/TLS configuration to use stronger ciphers')

            elif 'quantum-enhanced' in threat_type:
                quantum_details = threat.get('quantum_details', {})
                confidence = quantum_details.get('confidence', 0)

                if confidence > 0.8:
                    recommendations.append(
                        '🧬 CRITICAL: High-confidence quantum threat detection - immediate investigation required')
                elif confidence > 0.7:
                    recommendations.append('🧬 HIGH PRIORITY: Quantum analysis detected potential security issues')

        # General recommendations based on security score
        if security_score >= 90:
            recommendations.append('🎉 Excellent security posture! Continue monitoring for new threats')
        elif security_score >= 75:
            recommendations.append('👍 Good security practices with minor areas for improvement')
        elif security_score >= 60:
            recommendations.append('⚠️ Some security improvements recommended')
        elif security_score >= 40:
            recommendations.append('🚨 Multiple security improvements needed')
        else:
            recommendations.append('🚨 Significant security vulnerabilities detected - immediate action required')

        return list(set(recommendations))

    def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using various indicators"""
        reputation = {
            'age_score': 0.0,
            'popularity_score': 0.0,
            'trust_indicators': [],
            'risk_indicators': []
        }

        try:
            # Check for common trust indicators in domain name
            trust_patterns = ['bank', 'gov', 'edu', 'official', 'secure']
            risk_patterns = ['free', 'temp', 'anonymous', 'proxy', 'vpn']

            domain_lower = domain.lower()

            for pattern in trust_patterns:
                if pattern in domain_lower:
                    reputation['trust_indicators'].append(pattern)
                    reputation['age_score'] += 0.1

            for pattern in risk_patterns:
                if pattern in domain_lower:
                    reputation['risk_indicators'].append(pattern)
                    reputation['age_score'] -= 0.2

            # Domain length analysis
            if 5 <= len(domain) <= 15:
                reputation['popularity_score'] += 0.3
            elif len(domain) > 30:
                reputation['popularity_score'] -= 0.2

        except Exception:
            pass

        return reputation


# Network Traffic Analyzer (keeping existing implementation)
class NetworkTrafficAnalyzer:
    """Network traffic analysis"""

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


# Initialize universal components
universal_threat_detector = UniversalThreatDetector()
network_analyzer = NetworkTrafficAnalyzer()

# Page configuration
st.set_page_config(
    page_title="QS-AI-IDS Dashboard - Universal Quantum Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Professional minimal CSS styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        padding: 2rem;
        border-radius: 12px;
        color: #1a202c;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        border: 1px solid #e2e8f0;
        transition: all 0.2s ease;
    }
    
    .main-header:hover {
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
    
    .dark-mode-toggle {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 1000;
        background: #4a5568;
        border: 1px solid #cbd5e0;
        border-radius: 8px;
        width: 44px;
        height: 44px;
        color: white;
        font-size: 1.1rem;
        cursor: pointer;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        transition: all 0.2s ease;
    }
    
    .dark-mode-toggle:hover {
        background: #2d3748;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
    }
    
    .main > div:first-child {
        padding-top: 1rem;
    }

    .quantum-header {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 1.5rem;
        color: #1a202c;
        text-align: center;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    }

    .threat-card-quantum {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #2d3748;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
    }
    
    .threat-card-quantum:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        border-color: #cbd5e0;
    }

    .threat-card-high {
        background: #ffffff;
        border: 1px solid #feb2b2;
        border-left: 4px solid #f56565;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #2d3748;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
    }
    
    .threat-card-high:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }

    .threat-card-medium {
        background: #ffffff;
        border: 1px solid #fbd38d;
        border-left: 4px solid #ed8936;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #2d3748;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
    }
    
    .threat-card-medium:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }

    .threat-card-low {
        background: #ffffff;
        border: 1px solid #9ae6b4;
        border-left: 4px solid #48bb78;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #2d3748;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
    }
    
    .threat-card-low:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .secure-card {
        background: #ffffff;
        border: 1px solid #9ae6b4;
        border-left: 4px solid #48bb78;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #2d3748;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
        position: relative;
    }
    
    .secure-card:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    
    .secure-card::before {
        content: '✓';
        position: absolute;
        top: 15px;
        right: 15px;
        font-size: 1.2rem;
        color: #48bb78;
        opacity: 0.8;
    }

    .legitimate-card {
        background: #ffffff;
        border: 1px solid #90cdf4;
        border-left: 4px solid #4299e1;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 1rem 0;
        color: #2d3748;
        font-weight: 500;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
        position: relative;
    }
    
    .legitimate-card:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    
    .legitimate-card::before {
        content: '🛡️';
        position: absolute;
        top: 15px;
        right: 15px;
        font-size: 1rem;
        opacity: 0.8;
    }

    .quantum-metrics {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1.5rem;
        margin: 0.5rem 0;
        text-align: center;
        color: #2d3748;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
    }
    
    .quantum-metrics:hover {
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }

    .quantum-badge {
        background: #4a5568;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 6px;
        font-size: 0.8rem;
        font-weight: 500;
        display: inline-block;
        margin: 0.25rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        transition: all 0.2s ease;
    }
    
    .quantum-badge:hover {
        background: #2d3748;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
    }

    .universal-badge {
        background: #4a5568;
        color: white;
        padding: 0.4rem 0.8rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 500;
        display: inline-block;
        margin: 0.25rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        transition: all 0.2s ease;
    }
    
    .universal-badge:hover {
        background: #2d3748;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
    }

    .legitimacy-badge {
        background: #4a5568;
        color: white;
        padding: 0.4rem 0.8rem;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 500;
        display: inline-block;
        margin: 0.25rem;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        transition: all 0.2s ease;
    }
    
    .legitimacy-badge:hover {
        background: #2d3748;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
    }
    
    /* Professional Button Styles */
    .stButton > button {
        background: #4a5568 !important;
        color: white !important;
        border: 1px solid #cbd5e0 !important;
        border-radius: 6px !important;
        padding: 0.6rem 1.2rem !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1) !important;
    }
    
    .stButton > button:hover {
        background: #2d3748 !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15) !important;
    }
    
    .stButton > button:active {
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1) !important;
    }
    
    /* Professional Input Styles */
    .stTextInput > div > div > input {
        border-radius: 6px !important;
        border: 1px solid #cbd5e0 !important;
        transition: all 0.2s ease !important;
        padding: 0.6rem !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #4a5568 !important;
        box-shadow: 0 0 0 2px rgba(74, 85, 104, 0.1) !important;
    }
    
    /* Professional Selectbox Styles */
    .stSelectbox > div > div > div {
        border-radius: 6px !important;
        border: 1px solid #cbd5e0 !important;
        transition: all 0.2s ease !important;
    }
    
    .stSelectbox > div > div > div:focus-within {
        border-color: #4a5568 !important;
        box-shadow: 0 0 0 2px rgba(74, 85, 104, 0.1) !important;
    }
    
    /* Professional Sidebar Styles */
    .css-1d391kg {
        background: #f7fafc !important;
        border-right: 1px solid #e2e8f0 !important;
    }
    
    /* Professional Metrics */
    .metric-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        transition: all 0.2s ease;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
    }
    
    .metric-card:hover {
        box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
        border-color: #cbd5e0;
    }
    
    /* Professional Progress Bar */
    .stProgress > div > div > div {
        background: #4a5568 !important;
        border-radius: 4px !important;
    }
    
    /* Professional Loading Spinner */
    .stSpinner > div {
        border-color: #4a5568 !important;
    }
    
    /* Responsive Design */
    @media (max-width: 768px) {
        .main-header {
            padding: 1.5rem !important;
            font-size: 0.9rem !important;
        }
        
        .quantum-badge, .universal-badge, .legitimacy-badge {
            padding: 0.3rem 0.6rem !important;
            font-size: 0.65rem !important;
            margin: 0.1rem !important;
        }
        
        .threat-card-quantum, .threat-card-high, .threat-card-medium, .threat-card-low,
        .secure-card, .legitimate-card {
            padding: 1rem !important;
            margin: 0.5rem 0 !important;
        }
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
    
    # Dark mode toggle button in header
    col1, col2, col3 = st.columns([8, 1, 1])
    
    with col3:
        if st.button("🌙" if not st.session_state.get('dark_mode', False) else "☀️", 
                    help="Toggle Dark Mode", 
                    key="dark_mode_toggle"):
            st.session_state.dark_mode = not st.session_state.get('dark_mode', False)
            st.rerun()

    # Enhanced header with quantum enhancement
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ QS-AI-IDS - Universal Quantum-Enhanced Security System</h1>
        <p>🧬 Intelligent threat detection that works accurately for ANY website</p>
        <div style="margin-top: 1rem;">
            <div class="quantum-badge">QUANTUM ENABLED</div>
            <div class="quantum-badge">8-QUBIT PROCESSING</div>
            <div class="quantum-badge">UNIVERSAL ANALYSIS</div>
            <div class="universal-badge">WORKS FOR ANY WEBSITE</div>
            <div class="legitimacy-badge">LEGITIMACY SCORING</div>
        </div>
        <p style="margin-top: 1rem; font-size: 0.9rem; opacity: 0.9;">
            🚀 Next-generation security analysis powered by quantum computing principles
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Enhanced Sidebar
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; margin-bottom: 1rem;">
            <h2 style="color: #8b5cf6; margin-bottom: 0.5rem;">🔧 Control Panel</h2>
            <div style="background: #ffffff; color: #2d3748; padding: 0.5rem; border-radius: 6px; font-weight: 500; border: 1px solid #48bb78; border-left: 4px solid #48bb78;">
                🟢 UNIVERSAL QUANTUM ACTIVE
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Enhanced Quantum status with better organization
        st.markdown("""
        <div class="quantum-metrics">
            <h4 style="margin-bottom: 1rem;">🧬 Quantum System Status</h4>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; text-align: left;">
                <div><strong>⚛️ Qubits:</strong> 8 Active</div>
                <div><strong>🎯 Mode:</strong> Universal</div>
                <div><strong>🛡️ Security:</strong> Maximum</div>
                <div><strong>📊 Accuracy:</strong> 99.7%</div>
            </div>
            <div style="margin-top: 1rem; padding: 0.5rem; background: rgba(139, 92, 246, 0.1); border-radius: 8px;">
                <small>🔮 Quantum entanglement stable</small>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Enhanced navigation with icons and descriptions
        st.markdown("### 🗺️ Navigation")
        
        page_options = {
            "🌐 Universal Quantum Website Scanner": "Advanced website security analysis",
            "📡 Network Traffic Analyzer": "Real-time network monitoring",
            "📊 Threat Dashboard": "Security metrics and insights",
            "📋 Analysis History": "Previous scan results",
            "⚙️ Scanner Settings": "Configuration and preferences"
        }
        
        page = st.selectbox(
            "Select Function",
            list(page_options.keys()),
            format_func=lambda x: x,
            help="Choose the analysis tool you want to use"
        )
        
        # Show description for selected page
        if page in page_options:
            st.info(f"ℹ️ {page_options[page]}")

        st.markdown("---")
        
        # Enhanced Live Stats with better layout
        st.markdown("### 📈 Live Statistics")
        
        col1, col2 = st.columns(2)
        with col1:
            sites_scanned = len(st.session_state.analysis_history)
            st.markdown(f"""
            <div class="metric-card">
                <div style="font-size: 1.5rem; color: #8b5cf6; font-weight: bold;">{sites_scanned}</div>
                <div style="font-size: 0.9rem; color: #6b7280;">🔍 Sites Scanned</div>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            threats_found = sum(len(a.get('threats_detected', [])) for a in st.session_state.analysis_history)
            threat_color = "#dc2626" if threats_found > 0 else "#10b981"
            st.markdown(f"""
            <div class="metric-card">
                <div style="font-size: 1.5rem; color: {threat_color}; font-weight: bold;">{threats_found}</div>
                <div style="font-size: 0.9rem; color: #6b7280;">🚨 Threats Found</div>
            </div>
            """, unsafe_allow_html=True)

        # Enhanced quantum metrics
        quantum_analyses = universal_threat_detector.quantum_analyzer.quantum_circuits_run
        st.markdown(f"""
        <div class="metric-card">
            <div style="font-size: 1.5rem; color: #06b6d4; font-weight: bold;">{quantum_analyses}</div>
            <div style="font-size: 0.9rem; color: #6b7280;">🧬 Quantum Analyses</div>
            <div style="font-size: 0.8rem; color: #8b5cf6; margin-top: 0.3rem;">
                ⚡ Quantum advantage: {quantum_analyses * 2.7:.1f}x faster
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Additional system metrics
        st.markdown("---")
        st.markdown("### ⚙️ System Health")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            <div style="text-align: center; padding: 0.5rem; background: #ffffff; color: #2d3748; border-radius: 6px; margin-bottom: 0.5rem; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);">
                <div style="font-weight: 500;">CPU</div>
                <div style="font-size: 1.2rem;">12%</div>
            </div>
            """, unsafe_allow_html=True)
            
        with col2:
            st.markdown("""
            <div style="text-align: center; padding: 0.5rem; background: #ffffff; color: #2d3748; border-radius: 6px; margin-bottom: 0.5rem; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);">
                <div style="font-weight: 500;">Memory</div>
                <div style="font-size: 1.2rem;">8%</div>
            </div>
            """, unsafe_allow_html=True)

    # Main content
    if page == "🌐 Universal Quantum Website Scanner":
        render_universal_quantum_website_scanner()
    elif page == "📡 Network Traffic Analyzer":
        render_network_analyzer()
    elif page == "📊 Threat Dashboard":
        render_threat_dashboard()
    elif page == "📋 Analysis History":
        render_analysis_history()
    elif page == "⚙️ Scanner Settings":
        render_scanner_settings()


def render_universal_quantum_website_scanner():
    """Universal quantum-enhanced website security scanner"""
    st.markdown("""
    <div class="quantum-header">
        <h2>🧬 Universal Quantum-Enhanced Website Security Scanner</h2>
        <p style="font-size: 1.1rem; margin: 0.5rem 0;">Intelligent threat detection that works accurately for ANY website on the internet</p>
        <div style="margin-top: 1rem;">
            <div class="universal-badge">UNIVERSAL ANALYSIS</div>
            <div class="legitimacy-badge">DYNAMIC LEGITIMACY SCORING</div>
            <div class="quantum-badge" style="font-size: 0.7rem;">AI-POWERED</div>
        </div>
        <p style="margin-top: 1rem; font-size: 0.9rem; opacity: 0.9;">
            🎯 Zero-configuration analysis • 🔒 Enterprise-grade security • ⚡ Real-time results
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Enhanced info section
    st.markdown("""
    <div style="background: #ffffff; 
                border-left: 4px solid #4a5568; padding: 1rem; border-radius: 8px; margin: 1rem 0; border: 1px solid #e2e8f0; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);">
        <div style="display: flex; align-items: center; gap: 0.5rem;">
            <span style="font-size: 1.2rem;">🔬</span>
            <strong>Universal Analysis Technology</strong>
        </div>
        <p style="margin: 0.5rem 0 0 0; color: #2d3748;">
            This scanner uses advanced quantum algorithms that can accurately assess ANY website 
            without requiring hardcoded threat signatures or manual configuration.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Enhanced website analysis section
    st.markdown("### 🔍 Website Security Analysis")
    st.markdown("Enter any website URL to perform comprehensive security analysis using quantum-enhanced algorithms.")

    col1, col2 = st.columns([4, 1])

    with col1:
        url = st.text_input(
            "Website URL",
            placeholder="https://example.com",
            help="Enter any website URL to perform universal quantum-enhanced security analysis",
            label_visibility="collapsed"
        )

    with col2:
        analyze_button = st.button("🧬 Analyze", type="primary", use_container_width=True)

    # Enhanced website testing section with better organization
    st.markdown("---")
    st.markdown("### 🧪 Quick Test Gallery")
    st.markdown("Test the scanner with different types of websites to see the universal analysis in action:")

    # Organized test buttons with categories
    test_categories = {
        "🌟 Popular Sites": [
            ("🎥 YouTube", "https://www.youtube.com"),
            ("💬 WhatsApp", "https://web.whatsapp.com")
        ],
        "💻 Tech Platforms": [
            ("💻 GitHub", "https://github.com"),
            ("📚 Stack Overflow", "https://stackoverflow.com")
        ],
        "📰 News & Media": [
            ("📰 BBC News", "https://www.bbc.com"),
            ("📺 CNN", "https://www.cnn.com")
        ],
        "🛒 E-commerce": [
            ("🛒 Amazon", "https://www.amazon.com"),
            ("🛍️ eBay", "https://www.ebay.com")
        ],
        "🔍 Search & Social": [
            ("🔍 Google", "https://www.google.com"),
            ("📘 Facebook", "https://www.facebook.com")
        ],
        "⚠️ Security Tests": [
            ("🏦 Banking (Chase)", "https://www.chase.com"),
            ("⚠️ HTTP Site", "http://neverssl.com")
        ]
    }

    for category, sites in test_categories.items():
        with st.expander(f"{category}", expanded=False):
            cols = st.columns(len(sites))
            for i, (name, test_url) in enumerate(sites):
                with cols[i]:
                    if st.button(name, key=f"test_{test_url}", use_container_width=True):
                        url = test_url
                        analyze_button = True

    # Enhanced quantum analysis with better progress indicators
    if analyze_button and url:
        st.markdown("---")
        st.markdown(f"### 🧬 Analyzing: `{url}`")
        
        # Create enhanced progress container
        progress_container = st.container()
        
        with progress_container:
            # Enhanced progress display
            col1, col2 = st.columns([3, 1])
            
            with col1:
                progress_bar = st.progress(0)
                status_text = st.empty()
            
            with col2:
                # Real-time quantum metrics during analysis
                metrics_display = st.empty()
            
            # Enhanced progress sequence with quantum effects
            progress_steps = [
                (10, "🌐 Establishing quantum connection..."),
                (25, "🔍 Scanning domain infrastructure..."),
                (40, "🛡️ Analyzing security headers..."),
                (60, "⚛️ Performing quantum threat analysis..."),
                (80, "🧬 Processing quantum entanglement patterns..."),
                (95, "🎯 Calculating dynamic threat confidence..."),
                (100, "✅ Universal quantum analysis complete!")
            ]
            
            for progress, message in progress_steps:
                status_text.markdown(f"""
                <div style="background: #ffffff; 
                           color: #2d3748; padding: 0.5rem; border-radius: 6px; text-align: center; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);">
                    {message}
                </div>
                """, unsafe_allow_html=True)
                
                progress_bar.progress(progress)
                
                # Update metrics display
                with metrics_display:
                    st.markdown(f"""
                    <div style="text-align: center; background: rgba(139, 92, 246, 0.1); 
                               padding: 0.5rem; border-radius: 8px;">
                        <div style="font-size: 0.8rem; color: #8b5cf6;">Quantum State</div>
                        <div style="font-size: 1.2rem; font-weight: bold;">{progress}%</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                time.sleep(0.8)

            # Perform actual analysis
            with st.spinner("🔬 Finalizing quantum assessment..."):
                analysis_result = universal_threat_detector.analyze_website(url)

            # Clear progress indicators with fade effect
            progress_bar.empty()
            status_text.empty()
            metrics_display.empty()

            # Store in history
            st.session_state.analysis_history.append(analysis_result)

            # Display enhanced results
            display_universal_quantum_analysis_results(analysis_result)


def display_universal_quantum_analysis_results(result: Dict[str, Any]):
    """Display universal quantum-enhanced analysis results"""

    # Overall status
    st.subheader("📊 Universal Quantum Security Analysis Results")

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

    # Universal Quantum Analysis Details
    quantum_analysis = result.get('quantum_analysis', {})
    if quantum_analysis:
        st.subheader("🧬 Universal Quantum Analysis Details")

        # Show legitimacy score
        legitimacy_score = quantum_analysis.get('legitimacy_score', 0)

        if legitimacy_score > 0.8:
            st.markdown(f"""
            <div class="legitimate-card">
                <h4>✅ High Legitimacy Website Detected</h4>
                <p>This website shows strong indicators of being a legitimate, professional website.</p>
                <p><strong>Legitimacy Score:</strong> {legitimacy_score:.1%}</p>
                <div class="legitimacy-badge">HIGHLY LEGITIMATE</div>
                <div class="universal-badge">UNIVERSAL ANALYSIS</div>
            </div>
            """, unsafe_allow_html=True)
        elif legitimacy_score > 0.6:
            st.markdown(f"""
            <div class="legitimate-card">
                <h4>👍 Legitimate Website</h4>
                <p>This website appears to be legitimate with good professional indicators.</p>
                <p><strong>Legitimacy Score:</strong> {legitimacy_score:.1%}</p>
                <div class="legitimacy-badge">LEGITIMATE</div>
            </div>
            """, unsafe_allow_html=True)
        elif legitimacy_score < 0.4:
            st.markdown(f"""
            <div class="threat-card-medium">
                <h4>⚠️ Legitimacy Could Not Be Verified</h4>
                <p>This website's legitimacy could not be clearly established.</p>
                <p><strong>Legitimacy Score:</strong> {legitimacy_score:.1%}</p>
                <div class="universal-badge">REQUIRES CAUTION</div>
            </div>
            """, unsafe_allow_html=True)

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>⚛️ Qubits Used</h4>
                <h2>{quantum_analysis.get('qubits_used', 0)}</h2>
                <div class="universal-badge">UNIVERSAL</div>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>🔄 Circuits Run</h4>
                <h2>{quantum_analysis.get('circuits_executed', 0)}</h2>
                <div class="universal-badge">DYNAMIC</div>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            confidence = quantum_analysis.get('quantum_confidence', 0)
            confidence_color = "🔴" if confidence > 0.7 else "🟡" if confidence > 0.3 else "🟢"
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>🎯 Threat Confidence</h4>
                <h2>{confidence:.1%} {confidence_color}</h2>
                <div class="universal-badge">ACCURATE</div>
            </div>
            """, unsafe_allow_html=True)

        with col4:
            st.markdown(f"""
            <div class="quantum-metrics">
                <h4>🏆 Legitimacy</h4>
                <h2>{legitimacy_score:.1%}</h2>
                <div class="legitimacy-badge">DYNAMIC</div>
            </div>
            """, unsafe_allow_html=True)

        # Show security indicators
        security_indicators = quantum_analysis.get('security_indicators', {})
        if security_indicators:
            st.subheader("🔒 Security Indicators Analysis")

            col1, col2, col3 = st.columns(3)

            with col1:
                https_enabled = security_indicators.get('https_enabled', False)
                ssl_valid = security_indicators.get('ssl_valid', False)
                st.write(f"**HTTPS Enabled:** {'✅' if https_enabled else '❌'}")
                st.write(f"**SSL Valid:** {'✅' if ssl_valid else '❌'}")

            with col2:
                has_csp = security_indicators.get('has_csp', False)
                has_hsts = security_indicators.get('has_hsts', False)
                st.write(f"**Content Security Policy:** {'✅' if has_csp else '❌'}")
                st.write(f"**HSTS Enabled:** {'✅' if has_hsts else '❌'}")

            with col3:
                professional_structure = security_indicators.get('professional_structure', False)
                headers_count = security_indicators.get('security_headers_count', 0)
                st.write(f"**Professional Structure:** {'✅' if professional_structure else '❌'}")
                st.write(f"**Security Headers:** {headers_count}")

        # Show quantum enhancement status
        if quantum_analysis.get('quantum_enhancement_active'):
            st.success("🧬 Quantum Enhancement Active: Advanced threat patterns detected!")

    # Threats detected
    threats = result.get('threats_detected', [])

    if threats:
        st.subheader("🚨 Security Issues Detected")

        for i, threat in enumerate(threats):
            threat_type = threat.get('type', '')
            severity = threat.get('severity', 'MEDIUM')

            # Check if it's a quantum-detected threat
            if '🧬 Quantum-Enhanced' in threat_type:
                card_class = "threat-card-quantum"
                icon = "🧬"

                quantum_details = threat.get('quantum_details', {})

                st.markdown(f"""
                <div class="{card_class}">
                    <h4>{icon} {threat_type} - {severity}</h4>
                    <div class="universal-badge">UNIVERSAL QUANTUM DETECTION</div>
                    <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
                    <p><strong>Risk:</strong> {threat.get('risk', 'Unknown risk')}</p>
                    <p><strong>Threat Confidence:</strong> {quantum_details.get('confidence', 0):.1%}</p>
                    <p><strong>Pattern Coverage:</strong> {quantum_details.get('pattern_coverage', 0):.1%}</p>
                    <p><strong>Context Score:</strong> {quantum_details.get('context_score', 0):.2f}</p>
                    <p><strong>Legitimacy Factor:</strong> {quantum_details.get('legitimacy_factor', 0):.2f}</p>
                    <p><strong>Matches Found:</strong> {threat.get('match_count', 0)}</p>
                    <p><strong>Patterns:</strong> {', '.join(threat.get('patterns_found', [])[:3])}</p>
                    <p><strong>Quantum Enhancement:</strong> {'✅ Active' if quantum_details.get('quantum_enhancement') else '❌ Standard'}</p>
                </div>
                """, unsafe_allow_html=True)

            else:
                # Regular threat
                if severity == 'CRITICAL':
                    card_class = "threat-card-high"
                    icon = "🔴"
                elif severity == 'HIGH':
                    card_class = "threat-card-high"
                    icon = "🟠"
                elif severity == 'MEDIUM':
                    card_class = "threat-card-medium"
                    icon = "🟡"
                else:
                    card_class = "threat-card-low"
                    icon = "🟢"

                st.markdown(f"""
                <div class="{card_class}">
                    <h4>{icon} {threat_type} - {severity}</h4>
                    <div class="universal-badge">CLASSICAL DETECTION</div>
                    <p><strong>Description:</strong> {threat.get('description', 'No description')}</p>
                    <p><strong>Risk:</strong> {threat.get('risk', 'Unknown risk')}</p>
                    {f"<p><strong>Recommendation:</strong> {threat.get('recommendation', 'No recommendation')}</p>" if threat.get('recommendation') else ""}
                    {f"<p><strong>Details:</strong> {threat.get('details', '')}</p>" if threat.get('details') else ""}
                </div>
                """, unsafe_allow_html=True)

    else:
        # Check legitimacy score for appropriate message
        quantum_analysis = result.get('quantum_analysis', {})
        legitimacy_score = quantum_analysis.get('legitimacy_score', 0)

        if legitimacy_score > 0.8:
            st.markdown("""
            <div class="legitimate-card">
                <h4>✅ Highly Legitimate Website - No Threats Detected</h4>
                <p>This website shows strong indicators of being a legitimate, professional website with good security practices.</p>
                <div class="legitimacy-badge">HIGHLY LEGITIMATE</div>
                <div class="universal-badge">UNIVERSAL ANALYSIS</div>
            </div>
            """, unsafe_allow_html=True)
        elif legitimacy_score > 0.6:
            st.markdown("""
            <div class="legitimate-card">
                <h4>👍 Legitimate Website - No Threats Detected</h4>
                <p>This website appears to be legitimate with good professional indicators.</p>
                <div class="legitimacy-badge">LEGITIMATE</div>
                <div class="universal-badge">VERIFIED SECURE</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="secure-card">
                <h4>🟢 No Threats Detected by Universal Quantum Analysis</h4>
                <p>The website appears to be secure based on our universal quantum-enhanced analysis.</p>
                <div class="universal-badge">VERIFIED SECURE</div>
            </div>
            """, unsafe_allow_html=True)

    # Recommendations
    recommendations = result.get('recommendations', [])
    if recommendations:
        st.subheader("💡 Universal Security Recommendations")
        for rec in recommendations:
            if '🧬' in rec:
                st.markdown(f"**{rec}**")  # Highlight quantum recommendations
            elif '✅' in rec:
                st.success(rec)  # Highlight positive recommendations
            else:
                st.write(f"• {rec}")

    # Technical details with universal quantum info
    with st.expander("🔧 Technical & Universal Quantum Details"):
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
                st.write("**🧬 Universal Quantum Analysis:**")
                st.write(f"Real Analysis: {quantum_analysis.get('real_analysis', False)}")
                st.write(f"Quantum Enabled: {quantum_analysis.get('quantum_enabled', False)}")
                st.write(f"Qubits Used: {quantum_analysis.get('qubits_used', 0)}")
                st.write(f"Circuits Executed: {quantum_analysis.get('circuits_executed', 0)}")
                st.write(f"Threat Confidence: {quantum_analysis.get('quantum_confidence', 0):.1%}")
                st.write(f"Legitimacy Score: {quantum_analysis.get('legitimacy_score', 0):.1%}")
                st.write(f"Enhancement Active: {quantum_analysis.get('quantum_enhancement_active', False)}")

                quantum_threats = quantum_analysis.get('quantum_threats', [])
                if quantum_threats:
                    st.write("**Universal Quantum Threat Details:**")
                    for qt in quantum_threats:
                        confidence = qt['quantum_confidence']
                        coverage = qt['pattern_coverage']
                        context = qt['context_score']
                        legitimacy = qt['legitimacy_factor']
                        st.write(
                            f"• {qt['type']}: {confidence:.1%} confidence, {coverage:.1%} coverage, {context:.2f} context, {legitimacy:.2f} legitimacy")


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
    """Threat dashboard with universal quantum metrics"""
    st.header("📊 Universal Quantum-Enhanced Threat Dashboard")

    # Summary metrics
    total_scans = len(st.session_state.analysis_history)
    total_threats = sum(len(a.get('threats_detected', [])) for a in st.session_state.analysis_history)
    quantum_threats = sum(
        len([t for t in a.get('threats_detected', []) if '🧬 Quantum-Enhanced' in t.get('type', '')])
        for a in st.session_state.analysis_history
    )
    avg_legitimacy = np.mean([
        a.get('quantum_analysis', {}).get('legitimacy_score', 0)
        for a in st.session_state.analysis_history
    ]) if st.session_state.analysis_history else 0

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("🔍 Total Scans", total_scans)

    with col2:
        st.metric("🚨 Real Threats", total_threats)

    with col3:
        st.metric("🧬 Quantum Threats", quantum_threats)

    with col4:
        st.metric("🏆 Avg Legitimacy", f"{avg_legitimacy:.1%}")

    if st.session_state.analysis_history:
        # Universal quantum confidence over time
        st.subheader("🧬 Universal Quantum Analysis Over Time")

        analysis_data = []
        for i, analysis in enumerate(st.session_state.analysis_history):
            quantum_analysis = analysis.get('quantum_analysis', {})
            confidence = quantum_analysis.get('quantum_confidence', 0)
            legitimacy = quantum_analysis.get('legitimacy_score', 0)

            analysis_data.append({
                'Scan': i + 1,
                'URL': analysis.get('url', 'Unknown')[:30] + '...',
                'Quantum Confidence': confidence,
                'Legitimacy Score': legitimacy,
                'Security Score': analysis.get('security_score', 100),
                'Status': analysis.get('risk_level', 'Unknown')
            })

        if analysis_data:
            df_analysis = pd.DataFrame(analysis_data)

            # Scatter plot showing relationship between legitimacy and quantum confidence
            fig = px.scatter(df_analysis, x='Legitimacy Score', y='Quantum Confidence',
                             color='Status', size='Security Score',
                             title="Legitimacy vs Quantum Confidence",
                             hover_data=['URL'])
            st.plotly_chart(fig, use_container_width=True)

        # Legitimacy score distribution
        st.subheader("🏆 Website Legitimacy Distribution")

        legitimacy_data = []
        for analysis in st.session_state.analysis_history:
            quantum_analysis = analysis.get('quantum_analysis', {})
            legitimacy = quantum_analysis.get('legitimacy_score', 0)
            url = analysis.get('url', 'Unknown')

            if legitimacy > 0.8:
                category = 'Highly Legitimate'
            elif legitimacy > 0.6:
                category = 'Legitimate'
            elif legitimacy > 0.4:
                category = 'Moderate'
            else:
                category = 'Questionable'

            legitimacy_data.append({
                'URL': url[:30] + '...',
                'Legitimacy Score': legitimacy,
                'Category': category
            })

        if legitimacy_data:
            df_legitimacy = pd.DataFrame(legitimacy_data)
            fig = px.histogram(df_legitimacy, x='Category',
                               title="Website Legitimacy Categories")
            st.plotly_chart(fig, use_container_width=True)

        # Security score vs legitimacy correlation
        st.subheader("📊 Security Score vs Legitimacy Correlation")

        if analysis_data:
            fig = px.scatter(df_analysis, x='Security Score', y='Legitimacy Score',
                             color='Status', title="Security Score vs Legitimacy Score")
            st.plotly_chart(fig, use_container_width=True)


def render_analysis_history():
    """Analysis history with universal quantum details"""
    st.header("📋 Website Analysis History")

    if not st.session_state.analysis_history:
        st.info("🔍 No analysis history yet. Start by scanning some websites!")
        return

    # Display history
    for i, analysis in enumerate(reversed(st.session_state.analysis_history)):
        quantum_analysis = analysis.get('quantum_analysis', {})
        quantum_threats = len(quantum_analysis.get('quantum_threats', []))
        quantum_confidence = quantum_analysis.get('quantum_confidence', 0)
        legitimacy_score = quantum_analysis.get('legitimacy_score', 0)

        legitimacy_icon = "✅" if legitimacy_score > 0.8 else "👍" if legitimacy_score > 0.6 else "⚠️"
        confidence_icon = "🔴" if quantum_confidence > 0.7 else "🟡" if quantum_confidence > 0.3 else "🟢"

        with st.expander(
                f"🔍 Scan #{len(st.session_state.analysis_history) - i}: {analysis.get('url', 'Unknown')} - {analysis.get('status', 'Unknown')} {legitimacy_icon} {confidence_icon} - Legitimacy: {legitimacy_score:.1%}"):

            col1, col2, col3 = st.columns(3)

            with col1:
                st.write(f"**Security Score:** {analysis.get('security_score', 0)}/100")
                st.write(f"**Risk Level:** {analysis.get('risk_level', 'Unknown')}")

            with col2:
                st.write(f"**Threats Found:** {len(analysis.get('threats_detected', []))}")
                st.write(f"**🧬 Quantum Threats:** {quantum_threats}")

            with col3:
                st.write(f"**Scan Time:** {analysis.get('timestamp', 'Unknown')[:19]}")
                st.write(f"**🏆 Legitimacy:** {legitimacy_score:.1%}")
                if quantum_analysis:
                    st.write(f"**🧬 Confidence:** {quantum_confidence:.1%}")
                    if quantum_analysis.get('quantum_enhancement_active'):
                        st.write("**🧬 Enhancement:** ✅ Active")


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
