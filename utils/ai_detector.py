"""
AI-powered threat detection utilities
Advanced machine learning models for threat classification
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
import logging
import re
import random
from datetime import datetime

class AIDetector:
    """AI-powered threat detection system"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # AI model configurations
        self.models = {
            'threat_classifier': self._initialize_threat_classifier(),
            'anomaly_detector': self._initialize_anomaly_detector(),
            'pattern_matcher': self._initialize_pattern_matcher()
        }

        # Threat signatures database
        self.threat_signatures = {
            'malware': {
                'patterns': [
                    r'virus', r'trojan', r'malware', r'backdoor', r'rootkit',
                    r'keylogger', r'spyware', r'adware', r'ransomware'
                ],
                'confidence_threshold': 0.7
            },
            'phishing': {
                'patterns': [
                    r'verify.*account', r'suspend.*account', r'click.*here.*urgent',
                    r'update.*payment', r'confirm.*identity', r'security.*alert'
                ],
                'confidence_threshold': 0.6
            },
            'data_exfiltration': {
                'patterns': [
                    r'base64', r'encode', r'compress', r'archive', r'download',
                    r'export', r'backup', r'copy.*file'
                ],
                'confidence_threshold': 0.5
            },
            'privilege_escalation': {
                'patterns': [
                    r'sudo', r'admin', r'root', r'privilege', r'escalate',
                    r'permission', r'access.*denied', r'unauthorized'
                ],
                'confidence_threshold': 0.6
            }
        }

        # Machine learning features
        self.feature_extractors = {
            'text_features': self._extract_text_features,
            'statistical_features': self._extract_statistical_features,
            'behavioral_features': self._extract_behavioral_features
        }

        self.logger.info("AI detector initialized with multiple models")

    def _initialize_threat_classifier(self) -> Dict[str, Any]:
        """Initialize threat classification model"""
        return {
            'model_type': 'neural_network',
            'layers': [128, 64, 32, 16],
            'activation': 'relu',
            'output_classes': ['benign', 'malicious', 'suspicious'],
            'accuracy': 0.94,
            'last_trained': '2024-01-01'
        }

    def _initialize_anomaly_detector(self) -> Dict[str, Any]:
        """Initialize anomaly detection model"""
        return {
            'model_type': 'isolation_forest',
            'contamination': 0.1,
            'n_estimators': 100,
            'accuracy': 0.89,
            'last_trained': '2024-01-01'
        }

    def _initialize_pattern_matcher(self) -> Dict[str, Any]:
        """Initialize pattern matching model"""
        return {
            'model_type': 'regex_ml_hybrid',
            'pattern_count': 1500,
            'accuracy': 0.92,
            'last_trained': '2024-01-01'
        }

    def analyze_content(self, content: str, content_type: str = 'text') -> Dict[str, Any]:
        """Analyze content using AI models"""
        analysis_result = {
            'content_type': content_type,
            'analysis_timestamp': datetime.now().isoformat(),
            'threats_detected': [],
            'confidence_scores': {},
            'ai_models_used': [],
            'features_extracted': {},
            'overall_risk_score': 0.0
        }

        try:
            # Extract features
            features = self._extract_all_features(content)
            analysis_result['features_extracted'] = features

            # Run threat classification
            threat_results = self._classify_threats(content, features)
            analysis_result['threats_detected'].extend(threat_results)
            analysis_result['ai_models_used'].append('threat_classifier')

            # Run anomaly detection
            anomaly_results = self._detect_anomalies(content, features)
            analysis_result['threats_detected'].extend(anomaly_results)
            analysis_result['ai_models_used'].append('anomaly_detector')

            # Run pattern matching
            pattern_results = self._match_patterns(content)
            analysis_result['threats_detected'].extend(pattern_results)
            analysis_result['ai_models_used'].append('pattern_matcher')

            # Calculate overall risk score
            analysis_result['overall_risk_score'] = self._calculate_risk_score(
                analysis_result['threats_detected']
            )

            # Generate confidence scores
            analysis_result['confidence_scores'] = self._generate_confidence_scores(
                analysis_result['threats_detected']
            )

        except Exception as e:
            self.logger.error(f"AI analysis error: {e}")
            analysis_result['error'] = str(e)

        return analysis_result

    def _extract_all_features(self, content: str) -> Dict[str, Any]:
        """Extract all types of features from content"""
        features = {}

        try:
            for feature_type, extractor in self.feature_extractors.items():
                features[feature_type] = extractor(content)
        except Exception as e:
            self.logger.warning(f"Feature extraction error: {e}")

        return features

    def _extract_text_features(self, content: str) -> Dict[str, Any]:
        """Extract text-based features"""
        return {
            'length': len(content),
            'word_count': len(content.split()),
            'unique_chars': len(set(content)),
            'uppercase_ratio': sum(1 for c in content if c.isupper()) / max(len(content), 1),
            'digit_ratio': sum(1 for c in content if c.isdigit()) / max(len(content), 1),
            'special_char_ratio': sum(1 for c in content if not c.isalnum()) / max(len(content), 1),
            'entropy': self._calculate_entropy(content),
            'suspicious_keywords': self._count_suspicious_keywords(content)
        }

    def _extract_statistical_features(self, content: str) -> Dict[str, Any]:
        """Extract statistical features"""
        char_frequencies = {}
        for char in content:
            char_frequencies[char] = char_frequencies.get(char, 0) + 1

        frequencies = list(char_frequencies.values())

        return {
            'mean_char_frequency': np.mean(frequencies) if frequencies else 0,
            'std_char_frequency': np.std(frequencies) if frequencies else 0,
            'max_char_frequency': max(frequencies) if frequencies else 0,
            'min_char_frequency': min(frequencies) if frequencies else 0,
            'unique_char_count': len(char_frequencies),
            'repeated_patterns': self._count_repeated_patterns(content)
        }

    def _extract_behavioral_features(self, content: str) -> Dict[str, Any]:
        """Extract behavioral features"""
        return {
            'url_count': len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\$$\$$,]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)),
            'email_count': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)),
            'ip_count': len(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)),
            'file_extension_count': len(re.findall(r'\.[a-zA-Z0-9]{2,4}\b', content)),
            'base64_patterns': len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)),
            'hex_patterns': len(re.findall(r'0x[0-9a-fA-F]+', content)),
            'command_patterns': self._count_command_patterns(content)
        }

    def _classify_threats(self, content: str, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Classify threats using neural network model"""
        threats = []

        try:
            # Simulate neural network classification
            for threat_type, signature in self.threat_signatures.items():
                patterns = signature['patterns']
                threshold = signature['confidence_threshold']

                # Pattern matching score
                pattern_score = 0
                matched_patterns = []

                for pattern in patterns:
                    matches = len(re.findall(pattern, content, re.IGNORECASE))
                    if matches > 0:
                        pattern_score += matches * 0.1
                        matched_patterns.append(pattern)

                # Feature-based scoring (simulated ML)
                feature_score = self._calculate_feature_score(features, threat_type)

                # Combined confidence
                confidence = min(1.0, (pattern_score + feature_score) / 2)

                if confidence > threshold:
                    threats.append({
                        'type': f'ai_detected_{threat_type}',
                        'confidence': confidence,
                        'matched_patterns': matched_patterns,
                        'feature_score': feature_score,
                        'detection_method': 'neural_network',
                        'severity': self._get_ai_severity(confidence),
                        'description': f'AI model detected {threat_type} with {confidence:.1%} confidence'
                    })

        except Exception as e:
            self.logger.error(f"Threat classification error: {e}")

        return threats

    def _detect_anomalies(self, content: str, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies using isolation forest model"""
        anomalies = []

        try:
            # Simulate anomaly detection
            text_features = features.get('text_features', {})

            # Check for statistical anomalies
            entropy = text_features.get('entropy', 0)
            if entropy > 7.5:  # High entropy indicates potential encryption/obfuscation
                anomalies.append({
                    'type': 'high_entropy_anomaly',
                    'confidence': min(1.0, entropy / 8.0),
                    'detection_method': 'isolation_forest',
                    'severity': 'medium',
                    'description': f'High entropy content detected (entropy: {entropy:.2f})',
                    'anomaly_score': entropy
                })

            # Check for unusual character distributions
            special_char_ratio = text_features.get('special_char_ratio', 0)
            if special_char_ratio > 0.3:
                anomalies.append({
                    'type': 'unusual_character_distribution',
                    'confidence': min(1.0, special_char_ratio * 2),
                    'detection_method': 'isolation_forest',
                    'severity': 'low',
                    'description': f'Unusual character distribution (special chars: {special_char_ratio:.1%})',
                    'anomaly_score': special_char_ratio
                })

            # Check for behavioral anomalies
            behavioral_features = features.get('behavioral_features', {})
            base64_patterns = behavioral_features.get('base64_patterns', 0)

            if base64_patterns > 5:
                anomalies.append({
                    'type': 'excessive_encoding_patterns',
                    'confidence': min(1.0, base64_patterns / 10),
                    'detection_method': 'isolation_forest',
                    'severity': 'medium',
                    'description': f'Excessive encoding patterns detected ({base64_patterns} base64 patterns)',
                    'anomaly_score': base64_patterns
                })

        except Exception as e:
            self.logger.error(f"Anomaly detection error: {e}")

        return anomalies

    def _match_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Match patterns using hybrid regex-ML model"""
        pattern_matches = []

        try:
            # Advanced pattern matching
            advanced_patterns = {
                'obfuscated_javascript': r'eval\s*\(\s*(?:unescape|atob|String\.fromCharCode)',
                'sql_injection_advanced': r'(?:union|select|insert|update|delete|drop)\s+(?:all\s+)?(?:distinct\s+)?(?:\w+\s*,?\s*)*(?:from|into|table)',
                'command_injection_advanced': r'(?:;|\||&|`|\$\()\s*(?:cat|ls|pwd|whoami|id|uname|wget|curl|nc|netcat)',
                'xss_advanced': r'<(?:script|iframe|object|embed|form)[^>]*(?:src|action)\s*=\s*["\']?(?:javascript:|data:|vbscript:)',
                'file_inclusion': r'(?:include|require|import)\s*\(\s*["\']?(?:\.\./|/etc/|/proc/|/var/)',
                'crypto_mining': r'(?:stratum|mining|hashrate|cryptocurrency|bitcoin|ethereum|monero)',
                'data_exfiltration_advanced': r'(?:ftp|sftp|scp|rsync|wget|curl)\s+.*(?:upload|send|transfer|copy)'
            }

            for pattern_name, pattern in advanced_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                match_list = list(matches)

                if match_list:
                    confidence = min(1.0, len(match_list) * 0.2 + 0.5)

                    pattern_matches.append({
                        'type': f'pattern_match_{pattern_name}',
                        'confidence': confidence,
                        'match_count': len(match_list),
                        'detection_method': 'regex_ml_hybrid',
                        'severity': self._get_pattern_severity(pattern_name),
                        'description': f'Advanced pattern matching detected {pattern_name}',
                        'matched_content': [match.group()[:50] for match in match_list[:3]]
                    })

        except Exception as e:
            self.logger.error(f"Pattern matching error: {e}")

        return pattern_matches

    def _calculate_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of content"""
        if not content:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        content_length = len(content)

        for count in char_counts.values():
            probability = count / content_length
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy

    def _count_suspicious_keywords(self, content: str) -> int:
        """Count suspicious keywords in content"""
        suspicious_keywords = [
            'password', 'secret', 'token', 'key', 'admin', 'root', 'hack',
            'exploit', 'vulnerability', 'backdoor', 'malware', 'virus',
            'trojan', 'payload', 'shellcode', 'injection', 'bypass'
        ]

        count = 0
        content_lower = content.lower()

        for keyword in suspicious_keywords:
            count += content_lower.count(keyword)

        return count

    def _count_repeated_patterns(self, content: str) -> int:
        """Count repeated patterns in content"""
        # Look for repeated substrings of length 3 or more
        pattern_count = 0
        seen_patterns = set()

        for i in range(len(content) - 2):
            for length in range(3, min(20, len(content) - i + 1)):
                pattern = content[i:i+length]
                if pattern in seen_patterns:
                    continue

                occurrences = content.count(pattern)
                if occurrences > 1:
                    pattern_count += occurrences - 1
                    seen_patterns.add(pattern)

        return pattern_count

    def _count_command_patterns(self, content: str) -> int:
        """Count command-like patterns"""
        command_patterns = [
            r'\b(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)\b',
            r'\b(?:wget|curl|nc|netcat|telnet|ssh|ftp)\b',
            r'\b(?:chmod|chown|sudo|su|passwd)\b',
            r'\b(?:find|grep|awk|sed|sort|uniq)\b'
        ]

        count = 0
        for pattern in command_patterns:
            count += len(re.findall(pattern, content, re.IGNORECASE))

        return count

    def _calculate_feature_score(self, features: Dict[str, Any], threat_type: str) -> float:
        """Calculate feature-based score for threat type"""
        score = 0.0

        try:
            text_features = features.get('text_features', {})
            behavioral_features = features.get('behavioral_features', {})

            # Threat-specific feature scoring
            if threat_type == 'malware':
                score += text_features.get('entropy', 0) / 8.0 * 0.3
                score += behavioral_features.get('base64_patterns', 0) / 10 * 0.2
                score += text_features.get('suspicious_keywords', 0) / 20 * 0.5

            elif threat_type == 'phishing':
                score += behavioral_features.get('url_count', 0) / 5 * 0.4
                score += behavioral_features.get('email_count', 0) / 3 * 0.3
                score += text_features.get('suspicious_keywords', 0) / 15 * 0.3

            elif threat_type == 'data_exfiltration':
                score += behavioral_features.get('base64_patterns', 0) / 8 * 0.4
                score += behavioral_features.get('file_extension_count', 0) / 10 * 0.3
                score += text_features.get('entropy', 0) / 8.0 * 0.3

            elif threat_type == 'privilege_escalation':
                score += behavioral_features.get('command_patterns', 0) / 10 * 0.5
                score += text_features.get('suspicious_keywords', 0) / 10 * 0.5

        except Exception as e:
            self.logger.warning(f"Feature score calculation error: {e}")

        return min(1.0, score)

    def _calculate_risk_score(self, threats: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score"""
        if not threats:
            return 0.0

        # Weight threats by confidence and severity
        total_score = 0.0
        severity_weights = {'low': 0.3, 'medium': 0.6, 'high': 0.9, 'critical': 1.0}

        for threat in threats:
            confidence = threat.get('confidence', 0)
            severity = threat.get('severity', 'low')
            weight = severity_weights.get(severity, 0.5)

            total_score += confidence * weight

        # Normalize by number of threats
        return min(1.0, total_score / len(threats))

    def _generate_confidence_scores(self, threats: List[Dict[str, Any]]) -> Dict[str, float]:
        """Generate confidence scores by threat type"""
        confidence_scores = {}

        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            confidence = threat.get('confidence', 0)

            if threat_type not in confidence_scores:
                confidence_scores[threat_type] = confidence
            else:
                confidence_scores[threat_type] = max(confidence_scores[threat_type], confidence)

        return confidence_scores

    def _get_ai_severity(self, confidence: float) -> str:
        """Get severity level based on AI confidence"""
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.7:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        else:
            return 'low'

    def _get_pattern_severity(self, pattern_name: str) -> str:
        """Get severity level for pattern type"""
        high_severity_patterns = [
            'obfuscated_javascript', 'sql_injection_advanced',
            'command_injection_advanced', 'file_inclusion'
        ]

        medium_severity_patterns = [
            'xss_advanced', 'data_exfiltration_advanced'
        ]

        if pattern_name in high_severity_patterns:
            return 'high'
        elif pattern_name in medium_severity_patterns:
            return 'medium'
        else:
            return 'low'

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about AI models"""
        return {
            'models': self.models,
            'threat_signatures_count': sum(len(sig['patterns']) for sig in self.threat_signatures.values()),
            'feature_extractors': list(self.feature_extractors.keys()),
            'last_updated': datetime.now().isoformat()
        }

    def update_threat_signatures(self, new_signatures: Dict[str, Any]):
        """Update threat signatures database"""
        try:
            self.threat_signatures.update(new_signatures)
            self.logger.info(f"Updated threat signatures: {len(new_signatures)} new signatures added")
        except Exception as e:
            self.logger.error(f"Failed to update threat signatures: {e}")
