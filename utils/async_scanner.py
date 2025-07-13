import asyncio
import aiohttp
from urllib.parse import urlparse
import ssl
import time
import socket


class AsyncScanner:
    """
    Asynchronously scans a website and returns scan results.
    """

    def __init__(self, timeout=15):
        self.timeout = timeout

    async def scan_website(self, url):
        start_time = time.time()
        ip_address = "N/A (Initialization Failed)"  # Initialize with a more descriptive default
        ssl_info = {}  # Initialize SSL info

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            print(f"DEBUG: Hostname extracted: {hostname}")  # Debug print

            if hostname:
                try:
                    # Use getaddrinfo for more robust and non-blocking resolution in async contexts
                    # It returns a list of (family, type, proto, canonname, sockaddr) tuples
                    # We are interested in sockaddr[0] which is the IP address
                    addr_info = await asyncio.get_event_loop().getaddrinfo(hostname, None)
                    print(f"DEBUG: getaddrinfo result for {hostname}: {addr_info}")  # Debug print
                    if addr_info:
                        ip_address = addr_info[0][4][0]  # Pick the first IP address found
                        print(f"DEBUG: Resolved IP for {hostname}: {ip_address}")  # Debug print
                    else:
                        ip_address = "Could not resolve IP (getaddrinfo returned empty)"
                        print(f"DEBUG: getaddrinfo returned empty for {hostname}")  # Debug print
                except socket.gaierror as e:
                    ip_address = f"Could not resolve IP (DNS error): {e}"
                    print(f"DEBUG: DNS error for {hostname}: {e}")  # Debug print
                except Exception as e:
                    ip_address = f"Error resolving IP (general): {e}"
                    print(f"DEBUG: General error resolving IP for {hostname}: {e}")  # Debug print
            else:
                ip_address = "No hostname in URL"
                print(f"DEBUG: No hostname found in URL: {url}")  # Debug print

            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                try:
                    # Use a default SSL context for the request
                    async with session.get(url, ssl=ssl.SSLContext()) as response:
                        end_time = time.time()

                        # Attempt to get basic SSL info from the response
                        if response.url.scheme == 'https':
                            try:
                                # This gets the underlying SSLObject from aiohttp
                                ssl_object = response.connection.transport.get_extra_info('ssl_object')
                                if ssl_object:
                                    cert = ssl_object.getpeercert()
                                    ssl_info['version'] = ssl_object.version()
                                    ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])
                                    ssl_info['subject'] = dict(x[0] for x in cert['subject'])
                                    ssl_info['expires'] = cert['notAfter']
                                    ssl_info['error'] = None
                                else:
                                    ssl_info = {"status": "HTTPS used, but detailed SSL info not available"}
                            except Exception as e:
                                ssl_info = {"error": f"Could not get detailed SSL info: {e}"}
                        else:
                            ssl_info = {"status": "HTTP (no SSL)"}

                        scan_results = {
                            'status_code': response.status,
                            'content': await response.text(),
                            'headers': dict(response.headers),
                            'ssl_info': ssl_info,  # Now populated with more details
                            'scan_time': end_time - start_time,
                            'ip_address': ip_address  # Use the resolved IP address
                        }
                        return scan_results
                except aiohttp.ClientError as e:
                    return {'error': f"AIOHTTP Client Error: {e}"}
                except Exception as e:
                    return {'error': f"Request Error: {e}"}

        except Exception as e:
            return {'error': f"Overall Scan Error: {e}"}


async def main():
    """
    Main function to demonstrate the async scanner.
    """
    scanner = AsyncScanner()
    url_to_scan = "https://example.com"
    results = await scanner.scan_website(url_to_scan)

    if 'error' in results:
        print(f"Error scanning {url_to_scan}: {results['error']}")
    else:
        print(f"Scan results for {url_to_scan}:")
        for key, value in results.items():
            print(f"{key}: {value}")


if __name__ == "__main__":
    asyncio.run(main())
