import re


class PatternAnalyzer:
    """Class to handle pattern analysis for security threats"""

    def __init__(self):
        # Initialize pattern database
        self.threat_patterns = self._initialize_threat_patterns()

    def _initialize_threat_patterns(self):
        """Initialize threat pattern database"""
        return {
            'sql_injection': {
                'malicious_patterns': [
                    r"(?:')?\s*(or|and)\s+1\s*=\s*1\s*(--|\#|/\*|$)",
                    r"union\s+all\s+select",
                    r"select\s+.*\s+from\s+information_schema",
                    r";\s*drop\s+table",
                    r";\s*insert\s+into",
                    r"SLEEP\(\d+\)",
                    r"BENCHMARK\(\d+,.*\)"
                ],
                'legitimate_indicators': [
                    r"<code>", r"<pre>", r"example", r"tutorial", r"learning"
                ],
                'severity': 'high'
            },
            'xss': {
                'malicious_patterns': [
                    r"<script.*?>.*?</script>",
                    r"javascript:.*?\(.*?\)",
                    r"on\w+\s*=\s*['\"].*?['\"]",
                    r"<img[^>]+src=[^>]+onerror=",
                    r"<iframe[^>]+src=",
                    r"document\.cookie",
                    r"eval\(.*?\)"
                ],
                'legitimate_indicators': [
                    r"<code>", r"<pre>", r"example", r"<!--"
                ],
                'severity': 'high'
            },
            'command_injection': {
                'malicious_patterns': [
                    r";\s*rm\s+-rf",
                    r";\s*cat\s+/etc/passwd",
                    r";\s*wget\s+",
                    r";\s*curl\s+",
                    r"\|\s*bash",
                    r"`.*?`",
                    r"\$\(.*?\)"
                ],
                'legitimate_indicators': [
                    r"<code>", r"<pre>", r"example", r"command line tutorial"
                ],
                'severity': 'critical'
            },
            'path_traversal': {
                'malicious_patterns': [
                    r"\.\.\/\.\.\/",
                    r"\.\.\\\.\.\\",
                    r"\/etc\/passwd",
                    r"C:\\Windows\\system32",
                    r"\/var\/www\/"
                ],
                'legitimate_indicators': [
                    r"<code>", r"<pre>", r"example", r"path explanation"
                ],
                'severity': 'medium'
            }
        }

    def analyze_patterns(self, content, content_type="html"):
        """Analyze content for malicious patterns"""
        results = {
            'matches': [],
            'threat_types': [],
            'confidence': 0.0
        }

        content_lower = content.lower()

        for threat_type, threat_data in self.threat_patterns.items():
            malicious_patterns = threat_data['malicious_patterns']
            legitimate_indicators = threat_data.get('legitimate_indicators', [])

            # Pattern matching logic
            for pattern in malicious_patterns:
                matches = list(re.finditer(pattern, content, re.IGNORECASE))
                if matches:
                    # Context verification logic
                    for match in matches:
                        is_legitimate_context = False
                        match_start = max(0, match.start() - 50)
                        match_end = min(len(content), match.end() + 50)
                        context = content[match_start:match_end]

                        # Check if the match is in a legitimate context
                        for legit_pattern in legitimate_indicators:
                            if re.search(legit_pattern, context, re.IGNORECASE):
                                is_legitimate_context = True
                                break

                        # Only add if not in a legitimate context
                        if not is_legitimate_context:
                            results['matches'].append({
                                'pattern': pattern,
                                'match_text': match.group(0),
                                'start': match.start(),
                                'end': match.end(),
                                'threat_type': threat_type,
                                'severity': threat_data.get('severity', 'medium')
                            })
                            if threat_type not in results['threat_types']:
                                results['threat_types'].append(threat_type)

        # Calculate overall confidence
        if results['matches']:
            # Base confidence on number and severity of matches
            base_confidence = min(0.95, len(results['matches']) * 0.1)

            # Adjust confidence based on severity
            severity_multiplier = 1.0
            for match in results['matches']:
                if match['severity'] == 'critical':
                    severity_multiplier = max(severity_multiplier, 1.2)
                elif match['severity'] == 'high':
                    severity_multiplier = max(severity_multiplier, 1.1)

            results['confidence'] = min(0.95, base_confidence * severity_multiplier)

        return results