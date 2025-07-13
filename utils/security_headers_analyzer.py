class SecurityHeadersAnalyzer:
  """Class to handle security headers analysis"""

  def __init__(self):
      self.security_headers_database = {
          'x-frame-options': {
              'description': 'Prevents clickjacking attacks',
              'recommendation': 'Add X-Frame-Options header with value DENY or SAMEORIGIN',
              'severity': 'HIGH',
              'valid_values': ['DENY', 'SAMEORIGIN']
          },
          'x-xss-protection': {
              'description': 'Prevents cross-site scripting attacks',
              'recommendation': 'Add X-XSS-Protection header with value 1; mode=block',
              'severity': 'MEDIUM',
              'valid_values': ['1', '1; mode=block']
          },
          'x-content-type-options': {
              'description': 'Prevents MIME type sniffing',
              'recommendation': 'Add X-Content-Type-Options header with value nosniff',
              'severity': 'MEDIUM',
              'valid_values': ['nosniff']
          },
          'strict-transport-security': {
              'description': 'Enforces HTTPS usage',
              'recommendation': 'Add Strict-Transport-Security header with max-age at least 31536000',
              'severity': 'HIGH',
              # Added more flexible valid_values for HSTS
              'valid_values': ['max-age=31536000', 'max-age=31536000; includeSubDomains', 'max-age=86400', 'max-age=31536000; includeSubDomains; preload']
          },
          'content-security-policy': {
              'description': 'Controls resources the user agent is allowed to load',
              'recommendation': 'Add Content-Security-Policy header with appropriate values',
              'severity': 'HIGH',
              'valid_values': []  # Many valid options
          },
          'referrer-policy': {
              'description': 'Controls referrer information sent with requests',
              'recommendation': 'Add Referrer-Policy header with appropriate value',
              'severity': 'LOW',
              'valid_values': ['no-referrer', 'no-referrer-when-downgrade', 'same-origin']
          },
          'permissions-policy': {
              'description': 'Controls browser features available to the site',
              'recommendation': 'Add Permissions-Policy header with appropriate restrictions',
              'severity': 'MEDIUM',
              'valid_values': []  # Many valid options
          }
      }

  def analyze_headers(self, headers):
      """Analyze security headers"""
      results = {
          'missing_headers': [],
          'invalid_headers': [],
          'score': 0.0,
          'recommendations': []
      }

      # Convert headers to lowercase for comparison
      headers_lower = {k.lower(): v for k, v in headers.items()}

      # Check for missing headers
      for header, data in self.security_headers_database.items():
          header_present = header in headers_lower
          header_value = headers_lower.get(header, '')

          if not header_present:
              results['missing_headers'].append({
                  'header': header,
                  'severity': data['severity'],
                  'recommendation': data['recommendation']
              })
          else:
              # Special handling for Content-Security-Policy: if present, consider valid for now
              if header == 'content-security-policy':
                  # CSP is complex, just check for presence. Further validation would require parsing the policy.
                  # If it's present, we assume it's an attempt at security.
                  pass
              elif data['valid_values'] and not any(val in header_value for val in data['valid_values']):
                  results['invalid_headers'].append({
                      'header': header,
                      'value': header_value,
                      'recommendation': f"Update {header} to use one of: {', '.join(data['valid_values'])}"
                  })

      # Calculate score
      total_headers = len(self.security_headers_database)
      # Count headers that are present AND valid
      valid_headers_count = 0
      for header, data in self.security_headers_database.items():
          if header in headers_lower:
              if not data['valid_values'] or any(val in headers_lower[header] for val in data['valid_values']):
                  valid_headers_count += 1

      results['score'] = valid_headers_count / total_headers if total_headers > 0 else 0.0

      # Generate recommendations
      for header in results['missing_headers']:
          results['recommendations'].append(header['recommendation'])

      for header in results['invalid_headers']:
          results['recommendations'].append(header['recommendation'])

      return results
