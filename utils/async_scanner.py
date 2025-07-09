import asyncio
import aiohttp
import ssl
import socket
from urllib.parse import urlparse
import time


class AsyncScanner:
    """Asynchronous website scanner for improved performance"""

    def __init__(self, timeout=10):
        self.timeout = timeout

    async def scan_website(self, url):
        """Scan website asynchronously"""
        start_time = time.time()
        results = {
            'url': url,
            'status_code': None,
            'content': None,
            'headers': {},
            'ssl_info': None,
            'error': None,
            'scan_time': 0
        }

        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()

            # Asynchronously get website content and headers
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout, ssl=ssl_context) as response:
                    results['status_code'] = response.status
                    results['headers'] = dict(response.headers)
                    results['content'] = await response.text()

            # Get SSL info in a separate task
            ssl_info = await self._get_ssl_info(url)
            results['ssl_info'] = ssl_info

        except aiohttp.ClientError as e:
            results['error'] = f"Request error: {str(e)}"
        except asyncio.TimeoutError:
            results['error'] = "Request timed out"
        except Exception as e:
            results['error'] = f"Error: {str(e)}"

        results['scan_time'] = time.time() - start_time
        return results

    async def _get_ssl_info(self, url):
        """Get SSL certificate info asynchronously"""
        ssl_info = {}

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            if parsed_url.scheme != 'https':
                return {'error': 'Not an HTTPS URL'}

            # This needs to be run in a thread pool as socket operations block
            ssl_info = await asyncio.get_event_loop().run_in_executor(
                None, self._get_ssl_info_sync, hostname, port
            )

        except Exception as e:
            ssl_info = {'error': str(e)}

        return ssl_info

    def _get_ssl_info_sync(self, hostname, port):
        """Synchronous part of SSL info retrieval (runs in thread pool)"""
        ssl_info = {}

        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=5) as sock:
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

                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
                    cipher_name = cipher[0] if cipher else ''
                    ssl_info['weak_cipher'] = any(weak in cipher_name for weak in weak_ciphers)

        except Exception as e:
            ssl_info = {
                'error': str(e),
                'certificate_valid': False,
                'weak_cipher': True
            }

        return ssl_info