import re
from urllib.parse import urlparse

class LegitimacyAnalyzer:
  """Class to analyze the legitimacy of a website based on various indicators."""

  def __init__(self):
      # Define weights for different legitimacy indicators
      self.weights = {
          'ssl_valid': 0.20,
          'security_headers_score': 0.25,
          'professional_structure': 0.15,
          'content_quality_indicators': 0.10,
          'contact_info_present': 0.10,
          'privacy_terms_present': 0.10,
          'known_legitimate_domain': 0.20, # Strong positive indicator
          'suspicious_keywords_count': -0.15, # Negative weight
          'excessive_redirects': -0.10, # Negative weight
          'short_content': -0.05 # Negative weight
      }

      # List of known legitimate domains for a strong positive boost
      self.known_legitimate_domains = [
          'google.com', 'amazon.com', 'github.com', 'microsoft.com',
          'apple.com', 'facebook.com', 'twitter.com', 'linkedin.com',
          'youtube.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com',
          'cnn.com', 'bbc.com', 'nytimes.com', 'ebay.com', 'etsy.com',
          'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com'
      ]

  def calculate_legitimacy(self, content, url, security_headers, ssl_info):
      """
      Calculates a legitimacy score for the website.
      Score ranges from 0.0 to 1.0.
      """
      score = 0.5 # Start with a neutral score

      # 1. SSL/TLS Certificate Validity
      if ssl_info and not ssl_info.get('error'):
          score += self.weights['ssl_valid']
      else:
          score -= self.weights['ssl_valid'] * 0.5 # Penalize for missing/invalid SSL

      # 2. Security Headers Score (assuming a score from SecurityHeadersAnalyzer)
      # This requires SecurityHeadersAnalyzer to return a score (0-1)
      # For now, we'll simulate or assume it's integrated.
      # Let's assume security_headers is already an analyzed result with a 'score' key
      if 'score' in security_headers:
          score += security_headers['score'] * self.weights['security_headers_score']
      else:
          # Fallback if security_headers is just raw headers, check for presence of key ones
          if 'strict-transport-security' in security_headers or 'Strict-Transport-Security' in security_headers:
              score += self.weights['security_headers_score'] * 0.3
          if 'x-frame-options' in security_headers or 'X-Frame-Options' in security_headers:
              score += self.weights['security_headers_score'] * 0.2
          if 'content-security-policy' in security_headers or 'Content-Security-Policy' in security_headers:
              score += self.weights['security_headers_score'] * 0.5


      # 3. Professional Website Structure
      if self._has_professional_structure(content):
          score += self.weights['professional_structure']

      # 4. Content Quality Indicators (e.g., presence of common professional links)
      if self._has_content_quality_indicators(content):
          score += self.weights['content_quality_indicators']

      # 5. Contact Information Presence
      if self._has_contact_info(content):
          score += self.weights['contact_info_present']

      # 6. Privacy Policy / Terms of Service Presence
      if self._has_privacy_terms(content):
          score += self.weights['privacy_terms_present']

      # 7. Known Legitimate Domain Check (strong positive boost)
      parsed_url = urlparse(url)
      domain = parsed_url.netloc
      if any(known_domain in domain for known_domain in self.known_legitimate_domains):
          score += self.weights['known_legitimate_domain']

      # Negative Indicators
      # 8. Suspicious Keywords (re-using from AI Detector's logic, but simplified)
      suspicious_keywords_count = self._count_suspicious_keywords(content)
      score -= min(0.2, suspicious_keywords_count * self.weights['suspicious_keywords_count']) # Cap penalty

      # 9. Excessive Redirects (assuming this info is available from scanner)
      # This would need to be passed from AsyncScanner or similar.
      # For now, let's assume a simple check if the URL changed significantly
      # if url != initial_url_after_redirects: # Placeholder
      #     score -= self.weights['excessive_redirects']

      # 10. Short Content (very little content can be suspicious)
      if len(content) < 500: # Arbitrary threshold for very short content
          score -= self.weights['short_content']

      # Ensure score is within 0.0 and 1.0
      return max(0.0, min(1.0, score))

  def _has_professional_structure(self, content):
      """Check for common professional HTML structural elements."""
      content_lower = content.lower()
      # Look for common structural tags
      structural_elements = ['<nav', '<header', '<footer', '<main', '<article', '<section', '<aside']
      # Also check for presence of a reasonable number of heading tags
      has_headings = len(re.findall(r'<h[1-6]>', content_lower)) >= 2
      return sum(1 for element in structural_elements if element in content_lower) >= 3 and has_headings

  def _has_content_quality_indicators(self, content):
      """Check for presence of common professional content links/text."""
      content_lower = content.lower()
      # Common links/text in footers or navigation
      indicators = [
          'privacy policy', 'terms of service', 'about us', 'contact us',
          'copyright', 'sitemap', 'blog', 'news', 'careers'
      ]
      return any(indicator in content_lower for indicator in indicators)

  def _has_contact_info(self, content):
      """Check for presence of contact information (email, phone, address)."""
      content_lower = content.lower()
      # Simple regex for email or phone number patterns
      email_pattern = r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b'
      phone_pattern = r'(\+\d{1,2}\s?)?($$\d{3}$$|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}'
      return bool(re.search(email_pattern, content_lower) or re.search(phone_pattern, content_lower))

  def _has_privacy_terms(self, content):
      """Check for presence of privacy policy or terms of service links/text."""
      content_lower = content.lower()
      return 'privacy policy' in content_lower or 'terms of service' in content_lower or 'terms & conditions' in content_lower

  def _count_suspicious_keywords(self, content: str) -> int:
      """Count suspicious keywords in content (simplified for legitimacy)."""
      suspicious_keywords = [
          'free money', 'win prize', 'urgent action required', 'claim now',
          'limited time offer', 'congratulations you won', 'click here to verify',
          'your account has been suspended', 'unauthorized access detected'
      ]
      count = 0
      content_lower = content.lower()
      for keyword in suspicious_keywords:
          count += content_lower.count(keyword)
      return count
