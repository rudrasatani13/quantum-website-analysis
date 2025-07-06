"""
Data processing utilities for QS-AI-IDS
Handles file analysis, data parsing, and threat extraction
"""

import pandas as pd
import numpy as np
import json
import csv
import re
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

class DataProcessor:
    """Data processing and analysis utilities"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Threat patterns for file analysis
        self.file_threat_patterns = {
            'sql_injection': [
                r'union\s+select', r'drop\s+table', r'insert\s+into',
                r'delete\s+from', r'or\s+1\s*=\s*1', r'and\s+1\s*=\s*1'
            ],
            'xss_patterns': [
                r'<script[^>]*>', r'javascript:', r'on\w+\s*=',
                r'alert\s*\(', r'document\.cookie', r'eval\s*\('
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*rm\s+',
                r';\s*wget\s+', r';\s*curl\s+', r'\|\s*nc\s+'
            ],
            'malicious_urls': [
                r'http://[^/]*\.tk/', r'http://[^/]*\.ml/',
                r'bit\.ly/', r'tinyurl\.com/', r'goo\.gl/'
            ]
        }

        self.logger.info("Data processor initialized")

    def process_csv_file(self, file_content: str) -> Dict[str, Any]:
        """Process CSV file for threats"""
        results = {
            'file_type': 'CSV',
            'threats_found': [],
            'total_rows': 0,
            'suspicious_patterns': [],
            'analysis_timestamp': datetime.now().isoformat()
        }

        try:
            # Parse CSV content
            lines = file_content.strip().split('\n')
            results['total_rows'] = len(lines) - 1  # Exclude header

            # Analyze each row
            for row_idx, line in enumerate(lines):
                for threat_type, patterns in self.file_threat_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            results['threats_found'].append({
                                'type': threat_type,
                                'location': f'Row {row_idx + 1}',
                                'pattern': pattern,
                                'content_preview': line[:100] + '...' if len(line) > 100 else line,
                                'severity': self._get_threat_severity(threat_type)
                            })

            # Additional CSV-specific analysis
            self._analyze_csv_structure(file_content, results)

        except Exception as e:
            self.logger.error(f"CSV processing error: {e}")
            results['error'] = str(e)

        return results

    def process_json_file(self, file_content: str) -> Dict[str, Any]:
        """Process JSON file for threats"""
        results = {
            'file_type': 'JSON',
            'threats_found': [],
            'total_keys': 0,
            'suspicious_patterns': [],
            'analysis_timestamp': datetime.now().isoformat()
        }

        try:
            # Parse JSON
            data = json.loads(file_content)
            results['total_keys'] = self._count_json_keys(data)

            # Analyze JSON content recursively
            self._analyze_json_recursive(data, results, path="root")

            # Check for malicious JSON patterns
            self._check_json_threats(file_content, results)

        except json.JSONDecodeError as e:
            results['error'] = f"Invalid JSON format: {e}"
        except Exception as e:
            self.logger.error(f"JSON processing error: {e}")
            results['error'] = str(e)

            self.logger.error(f"JSON processing error: {e}")
            results['error'] = str(e)

        return results

    def process_text_file(self, file_content: str) -> Dict[str, Any]:
        """Process text/log file for threats"""
        results = {
            'file_type': 'TEXT',
            'threats_found': [],
            'total_lines': 0,
            'suspicious_patterns': [],
            'analysis_timestamp': datetime.now().isoformat()
        }

        try:
            lines = file_content.split('\n')
            results['total_lines'] = len(lines)

            # Analyze each line
            for line_idx, line in enumerate(lines):
                for threat_type, patterns in self.file_threat_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            results['threats_found'].append({
                                'type': threat_type,
                                'location': f'Line {line_idx + 1}',
                                'pattern': pattern,
                                'content_preview': line.strip()[:100] + '...' if len(line.strip()) > 100 else line.strip(),
                                'severity': self._get_threat_severity(threat_type)
                            })

            # Check for log-specific threats
            self._analyze_log_patterns(file_content, results)

        except Exception as e:
            self.logger.error(f"Text processing error: {e}")
            results['error'] = str(e)

        return results

    def _analyze_csv_structure(self, content: str, results: Dict[str, Any]):
        """Analyze CSV structure for anomalies"""
        try:
            lines = content.strip().split('\n')
            if len(lines) < 2:
                return

            # Check for unusual delimiters
            first_line = lines[0]
            delimiters = [',', ';', '\t', '|']
            delimiter_counts = {d: first_line.count(d) for d in delimiters}

            # Check for suspicious column names
            suspicious_columns = ['password', 'secret', 'key', 'token', 'admin']
            for col in suspicious_columns:
                if col.lower() in first_line.lower():
                    results['suspicious_patterns'].append({
                        'type': 'suspicious_column',
                        'description': f'Potentially sensitive column: {col}',
                        'severity': 'medium'
                    })

        except Exception as e:
            self.logger.warning(f"CSV structure analysis error: {e}")

    def _analyze_json_recursive(self, data: Any, results: Dict[str, Any], path: str):
        """Recursively analyze JSON data"""
        try:
            if isinstance(data, dict):
                for key, value in data.items():
                    current_path = f"{path}.{key}"

                    # Check for suspicious keys
                    suspicious_keys = ['password', 'secret', 'token', 'api_key', 'private_key']
                    if any(sus_key in key.lower() for sus_key in suspicious_keys):
                        results['suspicious_patterns'].append({
                            'type': 'suspicious_key',
                            'location': current_path,
                            'description': f'Potentially sensitive key: {key}',
                            'severity': 'medium'
                        })

                    # Recursively analyze value
                    self._analyze_json_recursive(value, results, current_path)

            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    current_path = f"{path}[{idx}]"
                    self._analyze_json_recursive(item, results, current_path)

            elif isinstance(data, str):
                # Check string values for threats
                for threat_type, patterns in self.file_threat_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, data, re.IGNORECASE):
                            results['threats_found'].append({
                                'type': threat_type,
                                'location': path,
                                'pattern': pattern,
                                'content_preview': data[:100] + '...' if len(data) > 100 else data,
                                'severity': self._get_threat_severity(threat_type)
                            })

        except Exception as e:
            self.logger.warning(f"JSON recursive analysis error: {e}")

    def _check_json_threats(self, content: str, results: Dict[str, Any]):
        """Check for JSON-specific threats"""
        try:
            # Check for potential code injection in JSON
            dangerous_patterns = [
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\(',
                r'document\.',
                r'window\.',
                r'<script[^>]*>'
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    results['threats_found'].append({
                        'type': 'code_injection',
                        'location': 'JSON content',
                        'pattern': pattern,
                        'content_preview': 'Potential code injection detected',
                        'severity': 'high'
                    })

        except Exception as e:
            self.logger.warning(f"JSON threat check error: {e}")

    def _analyze_log_patterns(self, content: str, results: Dict[str, Any]):
        """Analyze log files for attack patterns"""
        try:
            # Common attack patterns in logs
            attack_patterns = {
                'brute_force': [r'failed\s+login', r'authentication\s+failed', r'invalid\s+password'],
                'directory_traversal': [r'\.\./', r'\.\.\\', r'%2e%2e%2f'],
                'sql_injection': [r'union\s+select', r'or\s+1\s*=\s*1', r'drop\s+table'],
                'xss_attempt': [r'<script>', r'javascript:', r'alert\('],
                'port_scan': [r'port\s+scan', r'nmap', r'masscan'],
                'ddos': [r'ddos', r'flood', r'amplification']
            }

            for attack_type, patterns in attack_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        results['threats_found'].append({
                            'type': f'log_{attack_type}',
                            'location': 'Log entries',
                            'pattern': pattern,
                            'content_preview': f'Found {len(matches)} occurrences',
                            'severity': self._get_threat_severity(attack_type)
                        })

        except Exception as e:
            self.logger.warning(f"Log pattern analysis error: {e}")

    def _count_json_keys(self, data: Any) -> int:
        """Count total keys in JSON structure"""
        count = 0
        try:
            if isinstance(data, dict):
                count += len(data)
                for value in data.values():
                    count += self._count_json_keys(value)
            elif isinstance(data, list):
                for item in data:
                    count += self._count_json_keys(item)
        except:
            pass
        return count

    def _get_threat_severity(self, threat_type: str) -> str:
        """Get severity level for threat type"""
        high_severity = ['sql_injection', 'command_injection', 'code_injection']
        medium_severity = ['xss_patterns', 'directory_traversal', 'brute_force']

        if threat_type in high_severity:
            return 'high'
        elif threat_type in medium_severity:
            return 'medium'
        else:
            return 'low'

    def generate_file_hash(self, content: str) -> str:
        """Generate SHA256 hash of file content"""
        return hashlib.sha256(content.encode()).hexdigest()

    def extract_metadata(self, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract file metadata"""
        return {
            'filename': file_info.get('name', 'unknown'),
            'size': file_info.get('size', 0),
            'type': file_info.get('type', 'unknown'),
            'upload_time': datetime.now().isoformat()
        }
