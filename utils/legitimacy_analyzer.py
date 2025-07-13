from urllib.parse import urlparse


class LegitimacyAnalyzer:
  """Class to handle website legitimacy analysis"""

  def calculate_legitimacy(self, content, url, security_headers, ssl_info):
      """Calculate website legitimacy score"""
      legitimacy_score = 0.0

      # Domain and URL analysis (25%)
      domain_score = self._analyze_domain(url)
      legitimacy_score += max(0, domain_score) * 0.25

      # SSL Certificate analysis (20%)
      ssl_score = self._analyze_ssl(ssl_info)
      legitimacy_score += ssl_score * 0.20

      # Security headers analysis (15%)
      headers_score = self._analyze_headers(security_headers)
      legitimacy_score += headers_score * 0.15

      # Content legitimacy analysis (40%)
      content_score = self._analyze_content(content)
      legitimacy_score += max(0.0, content_score) * 0.40

      return min(1.0, max(0.0, legitimacy_score))

  def _analyze_domain(self, url):
      """Analyze domain legitimacy"""
      domain_score = 0.0
      parsed_url = urlparse(url)
      domain = parsed_url.netloc.lower()

      # HTTPS usage - Increased weight for HTTPS
      if parsed_url.scheme == 'https':
          domain_score += 0.35 # Increased from 0.25

      # Domain structure analysis logic
      # ... (add more sophisticated checks here if needed)

      return domain_score

  def _analyze_ssl(self, ssl_info):
      """Analyze SSL certificate legitimacy"""
      ssl_score = 0.0

      if not ssl_info:
          return ssl_score

      # Check certificate validity - Increased weight
      if ssl_info.get('is_valid', False):
          ssl_score += 0.5 # Increased from 0.4

      # Check expiration (less penalizing for shorter, valid certs like Let's Encrypt)
      days_until_expiry = ssl_info.get('days_until_expiry', 0)
      if days_until_expiry > 90: # Still good for 3 months+
          ssl_score += 0.1
      elif days_until_expiry > 30: # Still acceptable for 1 month+
          ssl_score += 0.05
      # No strong penalty for shorter valid certs, focus on 'is_valid'

      # Check certificate authority reputation
      ca_reputation = ssl_info.get('issuer_reputation', 'unknown')
      if ca_reputation == 'high':
          ssl_score += 0.2
      elif ca_reputation == 'medium':
          ssl_score += 0.1

      # Check for strong cipher suite
      if ssl_info.get('cipher_strength', 'weak') == 'strong':
          ssl_score += 0.2

      return min(1.0, ssl_score)

  def _analyze_headers(self, security_headers):
      """Analyze security headers"""
      headers_score = 0.0

      if not security_headers:
          return headers_score

      # Check for essential security headers
      essential_headers = {
          'Strict-Transport-Security': 0.15,
          'Content-Security-Policy': 0.15,
          'X-Content-Type-Options': 0.1,
          'X-Frame-Options': 0.1,
          'X-XSS-Protection': 0.1,
          'Referrer-Policy': 0.1,
          'Permissions-Policy': 0.1,
          'Cache-Control': 0.1,
          'Clear-Site-Data': 0.1
      }

      for header, value in security_headers.items():
          if header in essential_headers and value:
              headers_score += essential_headers[header]

      return min(1.0, headers_score)

  def _analyze_content(self, content):
      """Analyze content legitimacy"""
      content_score = 0.0

      if not content:
          return content_score

      # Check for login forms with proper security
      if '<form' in content.lower():
          if 'method="post"' in content.lower() and 'https://' in content.lower():
              content_score += 0.15
          else:
              content_score -= 0.1 # Reduced penalty from 0.2 for insecure forms

      # Check for suspicious obfuscation - Reduced penalty
      obfuscation_indicators = ['eval(', 'document.write(', 'escape(', 'unescape(', 'fromCharCode']
      for indicator in obfuscation_indicators:
          if indicator in content:
              content_score -= 0.05 # Reduced penalty from 0.1

      # Check for external resources - Removed as a strong negative indicator
      # Many legitimate sites use numerous external scripts (CDNs, analytics, ads).
      # external_script_count = content.lower().count('src="http')
      # if external_script_count > 10:
      #     content_score -= 0.15

      # Check for contact information (legitimate sites usually have these)
      if any(x in content.lower() for x in ['contact us', 'about us', 'privacy policy', 'terms of service']):
          content_score += 0.15

      # Check for excessive popups/redirects - Adjusted threshold
      if any(x in content.lower() for x in ['window.location', 'document.location', 'window.open']):
          if content.lower().count('window.open') > 5: # Increased threshold from 3
              content_score -= 0.1

      # Base legitimacy score - Increased base score
      content_score += 0.8 # Increased from 0.7

      return min(1.0, max(0.0, content_score))
