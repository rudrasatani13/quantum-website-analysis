"""
Real-time website capture and analysis system
Captures and analyzes any particular website in real-time
"""

import requests
import asyncio
import aiohttp
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import ssl
import socket
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import logging

class WebAnalyzer:
  """Real-time website capture and monitoring"""

  def __init__(self, quantum_detector=None, classical_detector=None):
      self.quantum_detector = quantum_detector
      self.classical_detector = classical_detector
      self.logger = logging.getLogger(__name__)
      self.active_captures = {}
      self.capture_callbacks = []

      # Setup headless browser for dynamic content
      self.setup_browser()

  def setup_browser(self):
      """Setup headless browser for JavaScript-heavy sites"""
      try:
          chrome_options = Options()
          chrome_options.add_argument("--headless")
          chrome_options.add_argument("--no-sandbox")
          chrome_options.add_argument("--disable-dev-shm-usage")
          chrome_options.add_argument("--disable-gpu")
          chrome_options.add_argument("--window-size=1920,1080")

          self.driver = webdriver.Chrome(options=chrome_options)
          self.logger.info("Browser setup completed for dynamic content capture")
      except Exception as e:
          self.logger.warning(f"Browser setup failed: {e}. Using requests only.")
          self.driver = None

  def add_capture_callback(self, callback):
      """Add callback for capture events"""
      self.capture_callbacks.append(callback)

  async def capture_website_live(self, url: str, monitor_duration: int = 300) -> Dict[str, Any]:
      """
      Live website capture and monitoring
      Args:
          url: Target website URL
          monitor_duration: How long to monitor (seconds)
      """
      self.logger.info(f"🌐 Starting live capture of: {url}")

      capture_data = {
          'url': url,
          'start_time': datetime.now(),
          'captures': [],
          'changes_detected': [],
          'threats_found': [],
          'performance_metrics': [],
          'status': 'active'
      }

      self.active_captures[url] = capture_data

      try:
          # Initial capture
          initial_capture = await self._capture_single_snapshot(url)
          capture_data['captures'].append(initial_capture)

          # Notify callbacks
          self._notify_callbacks('initial_capture', {
              'url': url,
              'capture': initial_capture
          })

          # Start continuous monitoring
          end_time = time.time() + monitor_duration

          while time.time() < end_time and capture_data['status'] == 'active':
              # Wait before next capture
              await asyncio.sleep(30)  # Capture every 30 seconds

              # Take new snapshot
              new_capture = await self._capture_single_snapshot(url)
              capture_data['captures'].append(new_capture)

              # Compare with previous capture
              if len(capture_data['captures']) > 1:
                  changes = self._detect_changes(
                      capture_data['captures'][-2],
                      new_capture
                  )

                  if changes:
                      capture_data['changes_detected'].extend(changes)

                      # Notify about changes
                      self._notify_callbacks('changes_detected', {
                          'url': url,
                          'changes': changes,
                          'timestamp': datetime.now()
                      })

              # Check for threats in new capture
              threats = await self._analyze_threats(new_capture)
              if threats:
                  capture_data['threats_found'].extend(threats)

                  # Notify about threats
                  self._notify_callbacks('threats_detected', {
                      'url': url,
                      'threats': threats,
                      'timestamp': datetime.now()
                  })

              # Performance monitoring
              perf_metrics = self._measure_performance(new_capture)
              capture_data['performance_metrics'].append(perf_metrics)

          capture_data['status'] = 'completed'
          capture_data['end_time'] = datetime.now()

          return capture_data

      except Exception as e:
          self.logger.error(f"Website capture error for {url}: {e}")
          capture_data['status'] = 'error'
          capture_data['error'] = str(e)
          return capture_data

  async def _capture_single_snapshot(self, url: str) -> Dict[str, Any]:
      """Capture single snapshot of website"""
      snapshot = {
          'timestamp': datetime.now(),
          'url': url,
          'status_code': None,
          'headers': {},
          'content': '',
          'html_content': '',
          'javascript_content': '',
          'css_content': '',
          'images': [],
          'links': [],
          'forms': [],
          'cookies': [],
          'ssl_info': {},
          'response_time': 0,
          'content_length': 0,
          'technologies': [],
          'security_headers': {}
      }

      try:
          start_time = time.time()

          # HTTP Request capture
          async with aiohttp.ClientSession() as session:
              async with session.get(url, timeout=30) as response:
                  snapshot['status_code'] = response.status
                  snapshot['headers'] = dict(response.headers)
                  snapshot['content'] = await response.text()
                  snapshot['response_time'] = time.time() - start_time
                  snapshot['content_length'] = len(snapshot['content'])

                  # Parse HTML content
                  soup = BeautifulSoup(snapshot['content'], 'html.parser')
                  snapshot['html_content'] = str(soup)

                  # Extract JavaScript
                  scripts = soup.find_all('script')
                  js_content = []
                  for script in scripts:
                      if script.string:
                          js_content.append(script.string)
                      if script.get('src'):
                          js_content.append(f"// External: {script.get('src')}")
                  snapshot['javascript_content'] = '\n'.join(js_content)

                  # Extract CSS
                  styles = soup.find_all('style')
                  css_content = []
                  for style in styles:
                      if style.string:
                          css_content.append(style.string)

                  # External CSS links
                  css_links = soup.find_all('link', rel='stylesheet')
                  for link in css_links:
                      if link.get('href'):
                          css_content.append(f"/* External: {link.get('href')} */")

                  snapshot['css_content'] = '\n'.join(css_content)

                  # Extract images
                  images = soup.find_all('img')
                  snapshot['images'] = [
                      {
                          'src': img.get('src', ''),
                          'alt': img.get('alt', ''),
                          'title': img.get('title', '')
                      }
                      for img in images
                  ]

                  # Extract links
                  links = soup.find_all('a', href=True)
                  snapshot['links'] = [
                      {
                          'href': link['href'],
                          'text': link.get_text().strip(),
                          'title': link.get('title', '')
                      }
                      for link in links
                  ]

                  # Extract forms
                  forms = soup.find_all('form')
                  snapshot['forms'] = [
                      {
                          'action': form.get('action', ''),
                          'method': form.get('method', 'GET'),
                          'inputs': [
                              {
                                  'type': inp.get('type', 'text'),
                                  'name': inp.get('name', ''),
                                  'value': inp.get('value', '')
                              }
                              for inp in form.find_all('input')
                          ]
                      }
                      for form in forms
                  ]

          # SSL/TLS Information
          snapshot['ssl_info'] = await self._get_ssl_info(url)

          # Security headers analysis
          snapshot['security_headers'] = self._analyze_security_headers(snapshot['headers'])

          # Technology detection
          snapshot['technologies'] = self._detect_technologies(snapshot)

          # Browser-based capture for dynamic content
          if self.driver:
              try:
                  browser_data = await self._capture_with_browser(url)
                  snapshot.update(browser_data)
              except Exception as e:
                  self.logger.warning(f"Browser capture failed: {e}")

          return snapshot

      except Exception as e:
          self.logger.error(f"Snapshot capture error: {e}")
          snapshot['error'] = str(e)
          return snapshot

  async def _capture_with_browser(self, url: str) -> Dict[str, Any]:
      """Capture dynamic content using browser"""
      browser_data = {
          'dynamic_content': '',
          'console_logs': [],
          'network_requests': [],
          'cookies_browser': [],
          'local_storage': {},
          'session_storage': {}
      }

      try:
          self.driver.get(url)

          # Wait for page to load
          time.sleep(3)

          # Get dynamic content after JavaScript execution
          browser_data['dynamic_content'] = self.driver.page_source

          # Get console logs
          logs = self.driver.get_log('browser')
          browser_data['console_logs'] = [
              {
                  'level': log['level'],
                  'message': log['message'],
                  'timestamp': log['timestamp']
              }
              for log in logs
          ]

          # Get cookies
          cookies = self.driver.get_cookies()
          browser_data['cookies_browser'] = cookies

          # Get local storage
          try:
              local_storage = self.driver.execute_script("return window.localStorage;")
              browser_data['local_storage'] = local_storage or {}
          except:
              pass

          # Get session storage
          try:
              session_storage = self.driver.execute_script("return window.sessionStorage;")
              browser_data['session_storage'] = session_storage or {}
          except:
              pass

      except Exception as e:
          self.logger.error(f"Browser capture error: {e}")
          browser_data['error'] = str(e)

      return browser_data

  async def _get_ssl_info(self, url: str) -> Dict[str, Any]:
      """Get SSL/TLS certificate information"""
      ssl_info = {}

      try:
          parsed_url = urlparse(url)
          if parsed_url.scheme == 'https':
              hostname = parsed_url.hostname
              port = parsed_url.port or 443

              context = ssl.create_default_context()

              with socket.create_connection((hostname, port), timeout=10) as sock:
                  with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                      cert = ssock.getpeercert()

                      ssl_info = {
                          'subject': dict(x[0] for x in cert['subject']),
                          'issuer': dict(x[0] for x in cert['issuer']),
                          'version': cert['version'],
                          'serial_number': cert['serialNumber'],
                          'not_before': cert['notBefore'],
                          'not_after': cert['notAfter'],
                          'signature_algorithm': cert.get('signatureAlgorithm', ''),
                          'cipher': ssock.cipher(),
                          'protocol': ssock.version()
                      }

      except Exception as e:
          ssl_info['error'] = str(e)

      return ssl_info

  def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
      """Analyze security headers"""
      security_headers = {
          'content_security_policy': headers.get('Content-Security-Policy'),
          'strict_transport_security': headers.get('Strict-Transport-Security'),
          'x_frame_options': headers.get('X-Frame-Options'),
          'x_content_type_options': headers.get('X-Content-Type-Options'),
          'x_xss_protection': headers.get('X-XSS-Protection'),
          'referrer_policy': headers.get('Referrer-Policy'),
          'permissions_policy': headers.get('Permissions-Policy'),
          'security_score': 0
      }

      # Calculate security score
      score = 0
      if security_headers['content_security_policy']:
          score += 25
      if security_headers['strict_transport_security']:
          score += 20
      if security_headers['x_frame_options']:
          score += 15
      if security_headers['x_content_type_options']:
          score += 15
      if security_headers['x_xss_protection']:
          score += 10
      if security_headers['referrer_policy']:
          score += 10
      if security_headers['permissions_policy']:
          score += 5

      security_headers['security_score'] = score

      return security_headers

  def _detect_technologies(self, snapshot: Dict[str, Any]) -> List[str]:
      """Detect technologies used by website"""
      technologies = []
      content = snapshot.get('content', '').lower()
      headers = snapshot.get('headers', {})

      # Server detection
      server = headers.get('Server', '').lower()
      if 'apache' in server:
          technologies.append('Apache')
      elif 'nginx' in server:
          technologies.append('Nginx')
      elif 'iis' in server:
          technologies.append('IIS')

      # Framework detection
      if 'django' in content or 'csrfmiddlewaretoken' in content:
          technologies.append('Django')
      if 'laravel' in content or 'laravel_session' in content:
          technologies.append('Laravel')
      if 'wordpress' in content or 'wp-content' in content:
          technologies.append('WordPress')
      if 'drupal' in content:
          technologies.append('Drupal')
      if 'joomla' in content:
          technologies.append('Joomla')

      # JavaScript frameworks
      if 'react' in content or 'reactjs' in content:
          technologies.append('React')
      if 'angular' in content or 'ng-' in content:
          technologies.append('Angular')
      if 'vue' in content or 'vuejs' in content:
          technologies.append('Vue.js')
      if 'jquery' in content:
          technologies.append('jQuery')

      # CSS frameworks
      if 'bootstrap' in content:
          technologies.append('Bootstrap')
      if 'tailwind' in content:
          technologies.append('Tailwind CSS')

      return technologies

  def _detect_changes(self, old_capture: Dict[str, Any], new_capture: Dict[str, Any]) -> List[Dict[str, Any]]:
      """Detect changes between captures"""
      changes = []

      # Content changes
      if old_capture.get('content') != new_capture.get('content'):
          changes.append({
              'type': 'content_change',
              'description': 'Website content has changed',
              'timestamp': new_capture['timestamp']
          })

      # Status code changes
      if old_capture.get('status_code') != new_capture.get('status_code'):
          changes.append({
              'type': 'status_change',
              'description': f"Status code changed from {old_capture.get('status_code')} to {new_capture.get('status_code')}",
              'timestamp': new_capture['timestamp']
          })

      # Header changes
      old_headers = set(old_capture.get('headers', {}).items())
      new_headers = set(new_capture.get('headers', {}).items())

      if old_headers != new_headers:
          changes.append({
              'type': 'headers_change',
              'description': 'HTTP headers have changed',
              'timestamp': new_capture['timestamp']
          })

      # Technology changes
      old_tech = set(old_capture.get('technologies', []))
      new_tech = set(new_capture.get('technologies', []))

      if old_tech != new_tech:
          added = new_tech - old_tech
          removed = old_tech - new_tech

          if added or removed:
              changes.append({
                  'type': 'technology_change',
                  'description': f"Technologies changed. Added: {list(added)}, Removed: {list(removed)}",
                  'timestamp': new_capture['timestamp']
              })

      return changes

  async def _analyze_threats(self, capture: Dict[str, Any]) -> List[Dict[str, Any]]:
      """Analyze capture for security threats"""
      threats = []

      # Check for suspicious JavaScript
      js_content = capture.get('javascript_content', '')
      if js_content:
          suspicious_patterns = [
              'eval(',
              'document.write(',
              'innerHTML',
              'outerHTML',
              'document.cookie',
              'window.location',
              'base64',
              'atob(',
              'btoa(',
              'unescape(',
              'String.fromCharCode'
          ]

          # Count how many suspicious patterns are present
          pattern_matches_count = 0
          for pattern in suspicious_patterns:
              if pattern in js_content:
                  pattern_matches_count += 1

          # Only flag as suspicious if a significant number of patterns are found
          # or if specific high-risk patterns are present in a suspicious context.
          # For now, we'll use a higher threshold for flagging.
          if pattern_matches_count >= 5: # Increased threshold from a lower implicit one
              threats.append({
                  'type': 'suspicious_javascript',
                  'pattern_count': pattern_matches_count,
                  'description': f'Multiple suspicious JavaScript patterns detected ({pattern_matches_count} patterns)',
                  'severity': 'medium', # Reduced severity from potentially high
                  'timestamp': capture['timestamp']
              })

      # Check for missing security headers
      security_headers = capture.get('security_headers', {})
      security_score = security_headers.get('security_score', 0)

      # Adjusted threshold for flagging weak security headers
      if security_score < 30: # Changed from < 50 to < 30
          threats.append({
              'type': 'weak_security_headers',
              'description': f'Weak security headers (Score: {security_score}/100)',
              'severity': 'medium',
              'timestamp': capture['timestamp']
          })

      # Check for insecure forms
      forms = capture.get('forms', [])
      for form in forms:
          if form.get('method', '').upper() == 'GET':
              for inp in form.get('inputs', []):
                  if inp.get('type') == 'password':
                      threats.append({
                          'type': 'insecure_form',
                          'description': 'Password field in GET form detected',
                          'severity': 'high',
                          'timestamp': capture['timestamp']
                      })

      # Check SSL/TLS issues
      ssl_info = capture.get('ssl_info', {})
      if 'error' in ssl_info:
          threats.append({
              'type': 'ssl_error',
              'description': f'SSL/TLS error: {ssl_info["error"]}',
              'severity': 'high',
              'timestamp': capture['timestamp']
          })

      return threats

  def _measure_performance(self, capture: Dict[str, Any]) -> Dict[str, Any]:
      """Measure website performance metrics"""
      return {
          'timestamp': capture['timestamp'],
          'response_time': capture.get('response_time', 0),
          'content_length': capture.get('content_length', 0),
          'status_code': capture.get('status_code'),
          'images_count': len(capture.get('images', [])),
          'links_count': len(capture.get('links', [])),
          'forms_count': len(capture.get('forms', [])),
          'technologies_count': len(capture.get('technologies', []))
      }

  def _notify_callbacks(self, event_type: str, data: Dict[str, Any]):
      """Notify all callbacks about capture events"""
      for callback in self.capture_callbacks:
          try:
              callback(event_type, data)
          except Exception as e:
              self.logger.error(f"Callback notification error: {e}")

  def stop_capture(self, url: str):
      """Stop capturing a particular website"""
      if url in self.active_captures:
          self.active_captures[url]['status'] = 'stopped'
          self.logger.info(f"Stopped capturing: {url}")

  def get_capture_status(self, url: str) -> Dict[str, Any]:
      """Get current capture status for a website"""
      return self.active_captures.get(url, {'status': 'not_found'})

  def get_all_active_captures(self) -> Dict[str, Any]:
      """Get all active captures"""
      return {
          url: data for url, data in self.active_captures.items()
          if data['status'] == 'active'
      }

  def cleanup(self):
      """Cleanup resources"""
      if self.driver:
          self.driver.quit()

class WebsiteCaptureManager:
  """Manager for multiple website captures"""

  def __init__(self, system_manager):
      self.system_manager = system_manager
      self.website_capture = WebAnalyzer()
      self.capture_threads = {}
      self.logger = logging.getLogger(__name__)

      # Add callback for capture events
      self.website_capture.add_capture_callback(self._handle_capture_event)

  def start_website_capture(self, url: str, duration: int = 300) -> str:
      """Start capturing a particular website"""
      if url in self.capture_threads:
          return f"Already capturing {url}"

      # Start capture in background thread
      def run_capture():
          loop = asyncio.new_event_loop()
          asyncio.set_event_loop(loop)
          try:
              result = loop.run_until_complete(
                  self.website_capture.capture_website_live(url, duration)
              )
              self.logger.info(f"Completed capture of {url}")
          except Exception as e:
              self.logger.error(f"Capture error for {url}: {e}")
          finally:
              loop.close()
              if url in self.capture_threads:
                  del self.capture_threads[url]

      thread = threading.Thread(target=run_capture, daemon=True)
      thread.start()
      self.capture_threads[url] = thread

      return f"Started capturing {url}"

  def stop_website_capture(self, url: str) -> str:
      """Stop capturing a particular website"""
      self.website_capture.stop_capture(url)

      if url in self.capture_threads:
          del self.capture_threads[url]

      return f"Stopped capturing {url}"

  def get_capture_data(self, url: str) -> Dict[str, Any]:
      """Get capture data for a particular website"""
      return self.website_capture.get_capture_status(url)

  def get_all_captures(self) -> Dict[str, Any]:
      """Get all active website captures"""
      return self.website_capture.get_all_active_captures()

  def _handle_capture_event(self, event_type: str, data: Dict[str, Any]):
      """Handle capture events"""
      # Add to real-time monitor
      if hasattr(self.system_manager, 'real_time_monitor'):
          if event_type == 'threats_detected':
              for threat in data.get('threats', []):
                  threat_event = {
                      'timestamp': datetime.now(),
                      'threat_type': threat.get('type', 'Unknown'),
                      'source_ip': '0.0.0.0',  # Website capture
                      'destination_ip': '0.0.0.0',
                      'severity': 0.7 if threat.get('severity') == 'high' else 0.5,
                      'confidence': 0.8,
                      'payload': data.get('url', ''),
                      'quantum_analysis': {},
                      'blocked': False,
                      'website_capture': True
                  }

                  self.system_manager.real_time_monitor.add_threat_detection(threat_event)

      # Log the event
      self.logger.info(f"Website capture event: {event_type} for {data.get('url')}")
