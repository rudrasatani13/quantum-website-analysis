"""
Classical threat detection algorithms
"""

import re
import logging
from typing import Dict, List, Any
from datetime import datetime


class ClassicalThreatDetector:
    """Classical machine learning based threat detection"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Threat signatures
        self.signatures = {
            'sql_injection': [
                r'union\s+select',
                r'drop\s+table',
                r'insert\s+into',
                r'delete\s+from',
                r'update\s+set',
                r'or\s+1\s*=\s*1',
                r'and\s+1\s*=\s*1'
            ],
            'xss_attack': [
                r'<script[^>]*>',
                r'javascript:',
                r'on\w+\s*=',
                r'alert\s*\(',
                r'document\.cookie',
                r'eval\s*\('
            ],
            'command_injection': [
                r';\s*cat\s+',
                r';\s*ls\s+',
                r';\s*rm\s+',
                r';\s*wget\s+',
                r';\s*curl\s+',
                r'\|\s*nc\s+'
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%2e%2e%5c'
            ]
        }

        self.logger.info("Classical detector initialized")

    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze payload using classical pattern matching"""

        detections = []
        max_confidence = 0.0
        primary_threat = 'benign'

        for threat_type, patterns in self.signatures.items():
            matches = 0

            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    matches += 1

            if matches > 0:
                confidence = min(matches / len(patterns), 1.0)

                detections.append({
                    'type': threat_type,
                    'confidence': confidence,
                    'matches': matches
                })

                if confidence > max_confidence:
                    max_confidence = confidence
                    primary_threat = threat_type

        is_threat = max_confidence > 0.3

        return {
            'threat_detected': is_threat,
            'threat_type': primary_threat,
            'confidence': max_confidence,
            'all_detections': detections,
            'analysis_method': 'classical_signatures',
            'timestamp': datetime.now().isoformat()
        }

    def analyze_http_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HTTP request for threats"""

        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')

        # Combine all text for analysis
        combined_payload = f"{url} {body}"
        for header_name, header_value in headers.items():
            combined_payload += f" {header_name}:{header_value}"

        result = self.analyze_payload(combined_payload)

        # Add HTTP-specific analysis
        result['http_analysis'] = {
            'suspicious_headers': self._check_suspicious_headers(headers),
            'url_analysis': self._analyze_url(url),
            'method': request_data.get('method', 'GET')
        }

        return result

    def _check_suspicious_headers(self, headers: Dict[str, str]) -> List[str]:
        """Check for suspicious HTTP headers"""
        suspicious = []

        suspicious_patterns = {
            'user-agent': ['sqlmap', 'nikto', 'nmap', 'burp'],
            'x-forwarded-for': ['127.0.0.1', 'localhost'],
            'referer': ['javascript:', 'data:']
        }

        for header_name, header_value in headers.items():
            header_lower = header_name.lower()

            if header_lower in suspicious_patterns:
                for pattern in suspicious_patterns[header_lower]:
                    if pattern in header_value.lower():
                        suspicious.append(f"{header_name}: {pattern}")

        return suspicious

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for suspicious patterns"""

        analysis = {
            'length': len(url),
            'suspicious_params': [],
            'encoded_chars': 0,
            'suspicious_paths': []
        }

        # Check for suspicious parameters
        suspicious_params = ['cmd', 'exec', 'system', 'eval', 'file', 'dir']
        for param in suspicious_params:
            if param in url.lower():
                analysis['suspicious_params'].append(param)

        # Count encoded characters
        analysis['encoded_chars'] = url.count('%')

        # Check for suspicious paths
        suspicious_paths = ['admin', 'config', 'backup', 'test', 'debug']
        for path in suspicious_paths:
            if f"/{path}" in url.lower():
                analysis['suspicious_paths'].append(path)

        return analysis
