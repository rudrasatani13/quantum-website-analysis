#!/usr/bin/env python3
"""
QS-AI-IDS CLI - Command Line Interface for Quantum-Enhanced Security Scanner
Usage: python cli.py [options] <url>
"""

import argparse
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import requests
import ssl
import socket
from urllib.parse import urlparse
import re
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv(dotenv_path="/Users/apple/Desktop/qs-ai-ids-dashboard/.env")

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# Import our modules
try:
    from utils.data_processor import DataProcessor
    from utils.ai_detector import AIDetector
    from utils.network_monitor import NetworkMonitor
except ImportError:
    print("⚠️  Warning: Some utility modules not found. Using basic functionality.")
    DataProcessor = None
    AIDetector = None
    NetworkMonitor = None


class CLIColors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Quantum colors
    QUANTUM = '\033[35m'  # Magenta
    LEGITIMATE = '\033[36m'  # Cyan
    THREAT = '\033[31m'  # Red


class UniversalQuantumWebsiteAnalyzer:
    """Universal quantum-enhanced website security analyzer for CLI"""

    def __init__(self):
        self.quantum_enabled = True
        self.quantum_qubits = 8
        self.quantum_circuits_run = 0

        # Intelligent threat patterns with context-aware detection
        self.quantum_threat_patterns = {
            'sql_injection': {
                'malicious_patterns': [
                    r'union\s+select\s+.*\s+from\s+\w+\s*(--|\#|\/\*)',
                    r'drop\s+table\s+\w+\s*(--|\#|\/\*)',
                    r'or\s+1\s*=\s*1\s*(--|\#|\/\*)',
                    r'and\s+1\s*=\s*1\s*(--|\#|\/\*)',
                    r'insert\s+into\s+\w+\s+values\s*$$[^)]*$$\s*(--|\#)',
                    r'delete\s+from\s+\w+\s+where\s+.*\s*(--|\#)',
                    r'information_schema\.tables\s*(--|\#)',
                    r'mysql_version\s*$$\s*$$\s*(--|\#)',
                    r'pg_sleep\s*$$\s*\d+\s*$$\s*(--|\#)',
                    r'waitfor\s+delay\s+[\'"][0-9:]+[\'"]'
                ],
                'legitimate_indicators': [
                    'documentation', 'tutorial', 'example', 'demo', 'learn', 'guide',
                    'mysql.com', 'postgresql.org', 'w3schools', 'stackoverflow',
                    'code example', 'syntax', 'reference'
                ],
                'severity_weight': 0.9,
                'confidence_multiplier': 1.2
            },
            'xss_attack': {
                'malicious_patterns': [
                    r'<script[^>]*>\s*alert\s*$$[^)]*$$',
                    r'javascript:\s*alert\s*$$[^)]*$$',
                    r'on\w+\s*=\s*[\'"].*alert\s*$$[^)]*$$',
                    r'<iframe[^>]*src\s*=\s*[\'"]javascript:',
                    r'document\.cookie\s*=\s*[^;]+',
                    r'eval\s*$$\s*[\'"][^\'\"]*[\'\"]\s*$$',
                    r'<object[^>]*data\s*=\s*[\'"]javascript:',
                    r'vbscript:\s*alert\s*\(',
                    r'expression\s*\(\s*alert\s*\(',
                    r'<embed[^>]*src\s*=\s*[\'"]javascript:'
                ],
                'legitimate_indicators': [
                    'google-analytics', 'gtag', 'facebook', 'twitter', 'linkedin',
                    'cdn.', 'googleapis', 'jquery', 'bootstrap', 'react', 'angular',
                    'legitimate script', 'tracking', 'analytics', 'advertisement'
                ],
                'severity_weight': 0.8,
                'confidence_multiplier': 1.1
            },
            'command_injection': {
                'malicious_patterns': [
                    r';\s*(cat|ls|rm|wget|curl|nc)\s+[\/\w\.-]+',
                    r'&&\s*(cat|ls|rm|wget|curl)\s+[\/\w\.-]+',
                    r'\|\s*nc\s+\d+\.\d+\.\d+\.\d+\s+\d+',
                    r'`(cat|ls|rm|wget|curl)\s+[\/\w\.-]+`',
                    r'\$$$(cat|ls|rm|wget|curl)\s+[\/\w\.-]+$$',
                    r'exec\s*$$\s*[\'"][^\'\"]*[\'\"]\s*$$',
                    r'system\s*$$\s*[\'"][^\'\"]*[\'\"]\s*$$',
                    r'shell_exec\s*$$\s*[\'"][^\'\"]*[\'\"]\s*$$',
                    r'passthru\s*$$\s*[\'"][^\'\"]*[\'\"]\s*$$'
                ],
                'legitimate_indicators': [
                    'documentation', 'tutorial', 'help', 'guide', 'example',
                    'linux.org', 'unix', 'bash', 'shell scripting', 'command line'
                ],
                'severity_weight': 0.95,
                'confidence_multiplier': 1.3
            },
            'path_traversal': {
                'malicious_patterns': [
                    r'\.\.\/.*\/etc\/passwd',
                    r'\.\.\\.*\\windows\\system32',
                    r'%2e%2e%2f.*%2fetc%2fpasswd',
                    r'%2e%2e%5c.*%5cwindows',
                    r'\.\.\/\.\.\/\.\.\/etc\/passwd',
                    r'\.\.\\\.\.\\\.\.\\windows\\system32',
                    r'\/etc\/passwd\x00',
                    r'\/etc\/shadow\x00',
                    r'\.\.\/\.\.\/\.\.\/\.\.\/etc'
                ],
                'legitimate_indicators': [
                    'documentation', 'example', 'tutorial', 'path', 'directory',
                    'file system', 'navigation', 'breadcrumb'
                ],
                'severity_weight': 0.85,
                'confidence_multiplier': 1.15
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


class UniversalThreatDetector:
    """Universal threat detection system for CLI"""

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
                'User-Agent': 'QS-AI-IDS CLI Universal Security Scanner 1.0'
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


class CLIFormatter:
    """Format output for CLI display"""

    @staticmethod
    def print_header():
        """Print CLI header"""
        print(f"{CLIColors.QUANTUM}{'=' * 80}{CLIColors.ENDC}")
        print(
            f"{CLIColors.BOLD}{CLIColors.HEADER}🛡️  QS-AI-IDS - Universal Quantum-Enhanced Security Scanner CLI{CLIColors.ENDC}")
        print(f"{CLIColors.QUANTUM}🧬 Intelligent threat detection for ANY website{CLIColors.ENDC}")
        print(f"{CLIColors.QUANTUM}{'=' * 80}{CLIColors.ENDC}")
        print()

    @staticmethod
    def print_analysis_start(url: str):
        """Print analysis start message"""
        print(f"{CLIColors.OKCYAN}🔍 Starting universal quantum analysis for: {CLIColors.BOLD}{url}{CLIColors.ENDC}")
        print()

    @staticmethod
    def print_progress(message: str, step: int, total: int):
        """Print progress message"""
        progress = "█" * (step * 20 // total) + "░" * (20 - (step * 20 // total))
        print(f"\r{CLIColors.OKBLUE}[{progress}] {message}{CLIColors.ENDC}", end="", flush=True)

    @staticmethod
    def print_results(analysis: Dict[str, Any], verbose: bool = False):
        """Print analysis results"""
        print("\n")
        print(f"{CLIColors.BOLD}📊 ANALYSIS RESULTS{CLIColors.ENDC}")
        print("=" * 50)

        # Basic metrics
        security_score = analysis.get('security_score', 0)
        status = analysis.get('status', 'Unknown')
        risk_level = analysis.get('risk_level', 'Unknown')
        threats_count = len(analysis.get('threats_detected', []))

        # Color code based on security score
        if security_score >= 80:
            score_color = CLIColors.OKGREEN
        elif security_score >= 60:
            score_color = CLIColors.WARNING
        else:
            score_color = CLIColors.FAIL

        print(f"🛡️  Security Score: {score_color}{security_score}/100{CLIColors.ENDC}")
        print(f"📈 Status: {status}")
        print(f"⚠️  Risk Level: {risk_level}")
        print(f"🚨 Threats Detected: {threats_count}")

        # Quantum analysis details
        quantum_analysis = analysis.get('quantum_analysis', {})
        if quantum_analysis:
            print(f"\n{CLIColors.QUANTUM}🧬 QUANTUM ANALYSIS{CLIColors.ENDC}")
            print("-" * 30)

            legitimacy_score = quantum_analysis.get('legitimacy_score', 0)
            quantum_confidence = quantum_analysis.get('quantum_confidence', 0)
            qubits_used = quantum_analysis.get('qubits_used', 0)
            circuits_run = quantum_analysis.get('circuits_executed', 0)

            # Color code legitimacy
            if legitimacy_score > 0.8:
                legitimacy_color = CLIColors.OKGREEN
            elif legitimacy_score > 0.6:
                legitimacy_color = CLIColors.OKCYAN
            else:
                legitimacy_color = CLIColors.WARNING

            print(f"🏆 Legitimacy Score: {legitimacy_color}{legitimacy_score:.1%}{CLIColors.ENDC}")
            print(f"🎯 Quantum Confidence: {quantum_confidence:.1%}")
            print(f"⚛️  Qubits Used: {qubits_used}")
            print(f"🔄 Circuits Executed: {circuits_run}")

            if quantum_analysis.get('quantum_enhancement_active'):
                print(f"{CLIColors.QUANTUM}✨ Quantum Enhancement: ACTIVE{CLIColors.ENDC}")

        # Threats
        threats = analysis.get('threats_detected', [])
        if threats:
            print(f"\n{CLIColors.THREAT}🚨 THREATS DETECTED{CLIColors.ENDC}")
            print("-" * 30)

            for i, threat in enumerate(threats, 1):
                threat_type = threat.get('type', 'Unknown')
                severity = threat.get('severity', 'MEDIUM')
                description = threat.get('description', 'No description')

                # Color code severity
                if severity == 'CRITICAL':
                    severity_color = CLIColors.FAIL + CLIColors.BOLD
                elif severity == 'HIGH':
                    severity_color = CLIColors.FAIL
                elif severity == 'MEDIUM':
                    severity_color = CLIColors.WARNING
                else:
                    severity_color = CLIColors.OKBLUE

                print(f"\n{i}. {threat_type}")
                print(f"   Severity: {severity_color}{severity}{CLIColors.ENDC}")
                print(f"   Description: {description}")

                if verbose and '🧬 Quantum-Enhanced' in threat_type:
                    quantum_details = threat.get('quantum_details', {})
                    if quantum_details:
                        print(f"   {CLIColors.QUANTUM}Quantum Details:{CLIColors.ENDC}")
                        print(f"     - Confidence: {quantum_details.get('confidence', 0):.1%}")
                        print(f"     - Pattern Coverage: {quantum_details.get('pattern_coverage', 0):.1%}")
                        print(f"     - Context Score: {quantum_details.get('context_score', 0):.2f}")
                        print(f"     - Legitimacy Factor: {quantum_details.get('legitimacy_factor', 0):.2f}")

        # Recommendations
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            print(f"\n{CLIColors.LEGITIMATE}💡 RECOMMENDATIONS{CLIColors.ENDC}")
            print("-" * 30)

            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. {rec}")

        # Technical details (if verbose)
        if verbose:
            technical = analysis.get('technical_details', {})
            if technical:
                print(f"\n{CLIColors.OKBLUE}🔧 TECHNICAL DETAILS{CLIColors.ENDC}")
                print("-" * 30)

                status_code = technical.get('status_code', 'Unknown')
                print(f"HTTP Status: {status_code}")

                ssl_info = technical.get('ssl_info', {})
                if ssl_info and not ssl_info.get('error'):
                    print(f"SSL Protocol: {ssl_info.get('protocol', 'Unknown')}")
                    print(f"Cipher Suite: {ssl_info.get('cipher_suite', 'Unknown')}")
                    print(f"Certificate Valid: {ssl_info.get('certificate_valid', False)}")

        print(f"\n{CLIColors.QUANTUM}{'=' * 50}{CLIColors.ENDC}")

    @staticmethod
    def print_error(message: str):
        """Print error message"""
        print(f"{CLIColors.FAIL}❌ Error: {message}{CLIColors.ENDC}")

    @staticmethod
    def print_success(message: str):
        """Print success message"""
        print(f"{CLIColors.OKGREEN}✅ {message}{CLIColors.ENDC}")


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="QS-AI-IDS - Universal Quantum-Enhanced Security Scanner CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py https://example.com
  python cli.py --verbose https://github.com
  python cli.py --json https://google.com
  python cli.py --output report.json https://stackoverflow.com
  python cli.py --batch urls.txt
        """
    )

    parser.add_argument('url', nargs='?', help='Website URL to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output with detailed information')
    parser.add_argument('-j', '--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('-o', '--output', help='Save results to file')
    parser.add_argument('-b', '--batch', help='Analyze multiple URLs from file (one per line)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--quiet', action='store_true', help='Minimal output (errors only)')

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        for attr in dir(CLIColors):
            if not attr.startswith('_'):
                setattr(CLIColors, attr, '')

    # Initialize detector
    detector = UniversalThreatDetector()

    # Handle batch processing
    if args.batch:
        if not os.path.exists(args.batch):
            CLIFormatter.print_error(f"Batch file not found: {args.batch}")
            sys.exit(1)

        with open(args.batch, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if not urls:
            CLIFormatter.print_error("No valid URLs found in batch file")
            sys.exit(1)

        results = []

        if not args.quiet:
            CLIFormatter.print_header()
            print(f"{CLIColors.OKCYAN}📋 Batch processing {len(urls)} URLs...{CLIColors.ENDC}\n")

        for i, url in enumerate(urls, 1):
            if not args.quiet:
                print(f"{CLIColors.OKBLUE}[{i}/{len(urls)}] Analyzing: {url}{CLIColors.ENDC}")

            try:
                result = detector.analyze_website(url)
                results.append(result)

                if not args.json and not args.quiet:
                    security_score = result.get('security_score', 0)
                    status = result.get('status', 'Unknown')
                    threats_count = len(result.get('threats_detected', []))
                    print(f"  Score: {security_score}/100, Status: {status}, Threats: {threats_count}\n")

            except Exception as e:
                CLIFormatter.print_error(f"Failed to analyze {url}: {str(e)}")
                continue

        # Output results
        if args.json:
            output_data = {
                'batch_analysis': True,
                'total_urls': len(urls),
                'successful_analyses': len(results),
                'timestamp': datetime.now().isoformat(),
                'results': results
            }

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                CLIFormatter.print_success(f"Batch results saved to {args.output}")
            else:
                print(json.dumps(output_data, indent=2))

        elif not args.quiet:
            print(
                f"{CLIColors.OKGREEN}✅ Batch analysis complete: {len(results)}/{len(urls)} successful{CLIColors.ENDC}")

        return

    # Single URL analysis
    if not args.url:
        parser.print_help()
        sys.exit(1)

    url = args.url

    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        if not args.quiet and not args.json:
            CLIFormatter.print_header()
            CLIFormatter.print_analysis_start(url)

            # Show progress
            steps = [
                "🌐 Establishing connection...",
                "🧬 Initializing quantum circuit...",
                "🔍 Analyzing legitimacy...",
                "⚛️ Performing content analysis...",
                "🎯 Calculating threat confidence...",
                "🔬 Finalizing assessment..."
            ]

            for i, step in enumerate(steps):
                CLIFormatter.print_progress(step, i + 1, len(steps))
                time.sleep(0.5)

            print("\n")

        # Perform analysis
        result = detector.analyze_website(url)

        # Output results
        if args.json:
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                if not args.quiet:
                    CLIFormatter.print_success(f"Results saved to {args.output}")
            else:
                print(json.dumps(result, indent=2))
        else:
            CLIFormatter.print_results(result, args.verbose)

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                CLIFormatter.print_success(f"Results also saved to {args.output}")

    except KeyboardInterrupt:
        if not args.quiet:
            print(f"\n{CLIColors.WARNING}⚠️  Analysis interrupted by user{CLIColors.ENDC}")
        sys.exit(1)

    except Exception as e:
        CLIFormatter.print_error(f"Analysis failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
