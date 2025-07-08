"""
Classical threat detection using pattern matching and false-positive filtering
"""

import re
import logging
from typing import Dict, List, Any
from datetime import datetime
import os
import json

# Import the false positive filter utility
from utils.false_positive_filter import is_false_positive


class ClassicalThreatDetector:
    """Classical rule-based threat detector"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        # Load attack patterns from external JSON
        pattern_path = os.path.join("config", "attack_patterns.json")
        try:
            with open(pattern_path, "r") as f:
                self.patterns_config = json.load(f)
            self.logger.info("Attack patterns loaded successfully.")
        except Exception as e:
            self.logger.error(f"Failed to load attack patterns: {e}")
            self.patterns_config = {}

    def analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Analyze a string payload and return threat detection result"""
        detections = []
        max_confidence = 0.0
        primary_threat = 'benign'

        for threat_type, threat_info in self.patterns_config.items():
            patterns = threat_info.get("malicious_patterns", [])
            indicators = threat_info.get("legitimate_indicators", [])
            weight = threat_info.get("severity_weight", 1.0)
            multiplier = threat_info.get("confidence_multiplier", 1.0)

            matches = 0
            for pattern in patterns:
                try:
                    if re.search(pattern, payload, re.IGNORECASE):
                        matches += 1
                except re.error as regex_error:
                    self.logger.warning(f"Invalid regex in {threat_type}: {pattern} ({regex_error})")

            if matches > 0:
                # Check for false positives using legitimate indicators
                if is_false_positive(payload, indicators):
                    self.logger.info(f"[Filtered] False positive detected for threat: {threat_type}")
                    continue

                confidence = min(matches / len(patterns), 1.0) * multiplier

                detections.append({
                    'type': threat_type,
                    'confidence': round(confidence, 3),
                    'matches': matches,
                    'weight': weight
                })

                if confidence > max_confidence:
                    max_confidence = confidence
                    primary_threat = threat_type

        is_threat = max_confidence > 0.3

        return {
            'threat_detected': is_threat,
            'threat_type': primary_threat,
            'confidence': round(max_confidence, 3),
            'all_detections': detections,
            'analysis_method': 'classical_signatures',
            'timestamp': datetime.now().isoformat()
        }

    def analyze_http_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an HTTP request dictionary"""
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        method = request_data.get('method', 'GET')

        combined_payload = f"{url} {body}"
        for k, v in headers.items():
            combined_payload += f" {k}:{v}"

        base_result = self.analyze_payload(combined_payload)

        base_result['http_analysis'] = {
            'suspicious_headers': self._check_suspicious_headers(headers),
            'url_analysis': self._analyze_url(url),
            'method': method
        }

        return base_result

    def _check_suspicious_headers(self, headers: Dict[str, str]) -> List[str]:
        """Detect suspicious headers often used in attacks"""
        suspicious_headers = []
        keyword_map = {
            'user-agent': ['sqlmap', 'nikto', 'nmap', 'burp'],
            'x-forwarded-for': ['127.0.0.1', 'localhost'],
            'referer': ['javascript:', 'data:']
        }

        for header, value in headers.items():
            lower_header = header.lower()
            for keyword in keyword_map.get(lower_header, []):
                if keyword in value.lower():
                    suspicious_headers.append(f"{header}: {keyword}")

        return suspicious_headers

    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Basic URL analysis for suspicious components"""
        analysis = {
            'length': len(url),
            'suspicious_params': [],
            'encoded_chars': url.count('%'),
            'suspicious_paths': []
        }

        for param in ['cmd', 'exec', 'file', 'system', 'eval']:
            if param in url.lower():
                analysis['suspicious_params'].append(param)

        for path in ['admin', 'debug', 'config', 'backup']:
            if f"/{path}" in url.lower():
                analysis['suspicious_paths'].append(path)

        return analysis
