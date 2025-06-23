#!/usr/bin/env python3
import os
import sys
import time
import socket
import hashlib
import requests
import subprocess
import concurrent.futures
import ssl
import base64
import random
import string
import json
import logging
import re
import platform
import psutil
import itertools
from urllib.parse import urlparse
from datetime import datetime
try:
    import scapy.all as scapy
    from scapy.all import sniff, ARP, sr1, IP, TCP, ICMP
except ImportError:
    scapy = None

# Color codes for cross-platform compatibility
try:
    import colorama
    colorama.init()
    RED = colorama.Fore.RED + colorama.Style.BRIGHT
    GREEN = colorama.Fore.GREEN + colorama.Style.BRIGHT
    YELLOW = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    BLUE = colorama.Fore.BLUE + colorama.Style.BRIGHT
    CYAN = colorama.Fore.CYAN + colorama.Style.BRIGHT
    WHITE = colorama.Fore.WHITE + colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
except ImportError:
    RED, GREEN, YELLOW, BLUE, CYAN, WHITE, RESET = "", "", "", "", "", "", ""

# Setup logging
logging.basicConfig(filename='cyber_defense_log.txt', level=logging.DEBUG, 
                    format='%(asctime)s - %(message)s')

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def check_requirements():
    required = ['requests', 'colorama', 'scapy', 'psutil']
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"{RED}[!] Missing requirements: {', '.join(missing)}{RESET}")
        print(f"{YELLOW}[*] Install with: pip install {' '.join(missing)}{RESET}")
        input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")
        return False
    return True

def set_window_title(title):
    """Set window title (works on Windows & Unix)."""
    if os.name == 'nt':  # Windows
        os.system(f"title {title}")
    else:  # Linux/macOS
        os.system(f"echo -ne '\033]0;{title}\a'")
set_window_title("Thalorien - Made by Rifat")

def validate_ip_or_domain(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

def validate_ports(ports_str):
    try:
        if '-' in ports_str:
            start, end = map(int, ports_str.split('-'))
            if 1 <= start <= end <= 65535:
                return list(range(start, end + 1))
        else:
            ports = [int(p) for p in ports_str.split(',')]
            if all(1 <= p <= 65535 for p in ports):
                return ports
        return None
    except ValueError:
        return None

def port_scanner():
    clear_screen()
    print(f"{CYAN}[*] Port Scanner{RESET}")
    target = input(f"{YELLOW}Enter target IP or domain: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP or domain{RESET}")
        return
    ports = input(f"{YELLOW}Enter ports (e.g., 80,443 or 1-100): {RESET}").strip()
    ports = validate_ports(ports)
    if not ports:
        print(f"{RED}[!] Invalid port format{RESET}")
        return
    print(f"{BLUE}[*] Scanning {target}... (Ctrl+C to stop){RESET}")
    logging.info(f"Port scan initiated on {target}")
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "UNKNOWN"
                    print(f"{GREEN}[+] Port {port} ({service}) is OPEN{RESET}")
                    logging.debug(f"Open port: {target}:{port} ({service})")
        except Exception as e:
            logging.debug(f"Port scan error on {target}:{port} - {str(e)}")
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            concurrent.futures.wait(futures)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during scan: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def traceroute():
    clear_screen()
    print(f"{CYAN}[*] Traceroute{RESET}")
    target = input(f"{YELLOW}Enter target domain or IP: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP or domain{RESET}")
        return
    cmd = ["tracert" if platform.system() == "Windows" else "traceroute", target]
    try:
        subprocess.run(cmd, shell=(platform.system() == "Windows"), check=True)
        logging.info(f"Traceroute performed on {target}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error performing traceroute: {str(e)}{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] Traceroute not found. Install traceroute on Linux/Android.{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def whois_lookup():
    clear_screen()
    print(f"{CYAN}[*] WHOIS Lookup{RESET}")
    domain = input(f"{YELLOW}Enter domain: {RESET}").strip()
    cmd = ["whois", domain]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(f"{GREEN}[+] WHOIS Result:{RESET}\n{result.stdout}")
        logging.info(f"WHOIS lookup performed on {domain}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error performing WHOIS lookup: {e.stderr}{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] WHOIS not found. Install whois on Linux/Android.{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def dns_lookup():
    clear_screen()
    print(f"{CYAN}[*] DNS Lookup{RESET}")
    target = input(f"{YELLOW}Enter domain: {RESET}").strip()
    try:
        result = socket.gethostbyname_ex(target)
        print(f"{GREEN}[+] Result:{RESET}")
        print(f"Host: {result[0]}")
        print(f"Aliases: {result[1]}")
        print(f"IP Addresses: {result[2]}")
        logging.info(f"DNS lookup on {target}: {result}")
    except socket.gaierror:
        print(f"{RED}[!] Error: Could not resolve domain{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def robots_scanner():
    clear_screen()
    print(f"{CYAN}[*] Robots.txt Scanner{RESET}")
    url = input(f"{YELLOW}Enter website URL: {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        if not url.endswith("/"):
            url += "/"
        res = requests.get(url + "robots.txt", timeout=5)
        res.raise_for_status()
        print(f"{GREEN}[+] Robots.txt content:{RESET}\n{res.text}")
        logging.info(f"Robots.txt scanned for {url}")
    except (requests.RequestException, ValueError) as e:
        print(f"{RED}[!] Could not fetch robots.txt: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def google_dork():
    clear_screen()
    print(f"{CYAN}[*] Google Dork Generator{RESET}")
    dork = input(f"{YELLOW}Enter Google dork query: {RESET}").strip()
    if not dork:
        print(f"{RED}[!] Empty query{RESET}")
        return
    encoded_dork = dork.replace(' ', '+')
    print(f"{GREEN}[+] Use this in browser:{RESET}")
    print(f"https://www.google.com/search?q={encoded_dork}")
    logging.info(f"Google dork generated: {encoded_dork}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def generate_subdomains(max_length=3):
    """Generate all possible subdomains (a-z, 0-9) up to max_length."""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    subdomains = []
    for length in range(1, max_length + 1):
        for sub in itertools.product(chars, repeat=length):
            subdomains.append(''.join(sub))
    return subdomains

def subdomain_scanner():
    clear_screen()
    print(f"{CYAN}[*] Subdomain Scanner (Brute-Force Mode){RESET}")
    domain = input(f"{YELLOW}Enter domain: {RESET}").strip()
    max_length = int(input(f"{YELLOW}Max subdomain length (1-3 recommended): {RESET}").strip())
    
    wordlist = generate_subdomains(max_length)
    total = len(wordlist)
    print(f"{BLUE}[*] Scanning {total} subdomains for {domain}...{RESET}")
    
    found_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(socket.gethostbyname, f"{sub}.{domain}"): sub for sub in wordlist}
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                ip = future.result()
                print(f"{GREEN}[+] {sub}.{domain} => {ip}{RESET}")
                logging.info(f"Subdomain found: {sub}.{domain} => {ip}")
                found_count += 1
            except socket.gaierror:
                pass
            except Exception as e:
                logging.debug(f"Error on {sub}.{domain}: {str(e)}")
    
    print(f"\n{GREEN}[*] Scan completed. Found {found_count}/{total} subdomains.{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def http_headers():
    clear_screen()
    print(f"{CYAN}[*] HTTP Headers Viewer{RESET}")
    url = input(f"{YELLOW}Enter website URL: {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        print(f"{GREEN}[+] HTTP Headers:{RESET}")
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        logging.info(f"HTTP headers viewed for {url}")
    except (requests.RequestException, ValueError) as e:
        print(f"{RED}[!] Error fetching headers: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def payload_generator():
    clear_screen()
    print(f"{CYAN}[*] Payload Generator{RESET}")
    print(f"{WHITE}1. Base64 Encode")
    print("2. URL Encode")
    print(f"0. Back{RESET}")
    choice = input(f"{YELLOW}Select option: {RESET}").strip()
    if choice == "1":
        cmd = input(f"{YELLOW}Enter command to encode: {RESET}").strip()
        if not cmd:
            print(f"{RED}[!] Empty command{RESET}")
            return
        encoded = base64.b64encode(cmd.encode()).decode()
        print(f"{GREEN}[+] Base64 Encoded Payload:{RESET}\n{encoded}")
        logging.info(f"Base64 payload generated: {encoded}")
    elif choice == "2":
        cmd = input(f"{YELLOW}Enter command to encode: {RESET}").strip()
        if not cmd:
            print(f"{RED}[!] Empty command{RESET}")
            return
        encoded = requests.utils.quote(cmd)
        print(f"{GREEN}[+] URL Encoded Payload:{RESET}\n{encoded}")
        logging.info(f"URL encoded payload generated: {encoded}")
    elif choice == "0":
        return
    else:
        print(f"{RED}[!] Invalid choice{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def hash_cracker():
    clear_screen()
    print(f"{CYAN}[*] Hash Cracker{RESET}")
    hash_value = input(f"{YELLOW}Enter hash to crack: {RESET}").strip()
    if not hash_value:
        print(f"{RED}[!] Empty hash{RESET}")
        return
    wordlist = ["password", "admin", "letmein", "123456", "qwerty", "welcome", "12345", "bangladesh", "dhaka", "security"]
    print(f"{BLUE}[*] Attempting to crack hash...{RESET}")
    try:
        for word in wordlist:
            if hashlib.md5(word.encode()).hexdigest() == hash_value:
                print(f"{GREEN}[+] Found (MD5): {word}{RESET}")
                logging.info(f"Hash cracked (MD5): {hash_value} => {word}")
                return
            if hashlib.sha1(word.encode()).hexdigest() == hash_value:
                print(f"{GREEN}[+] Found (SHA1): {word}{RESET}")
                logging.info(f"Hash cracked (SHA1): {hash_value} => {word}")
                return
            if hashlib.sha256(word.encode()).hexdigest() == hash_value:
                print(f"{GREEN}[+] Found (SHA256): {word}{RESET}")
                logging.info(f"Hash cracked (SHA256): {hash_value} => {word}")
                return
        print(f"{RED}[!] Hash not cracked with wordlist{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error cracking hash: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def directory_enumeration():
    clear_screen()
    print(f"{CYAN}[*] Directory Enumeration{RESET}")
    url = input(f"{YELLOW}Enter website URL: {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        if not url.endswith("/"):
            url += "/"
        common_dirs = ["admin/", "login/", "wp-admin/", "backup/", "config/", "test/", "dashboard/", "panel/", "uploads/", "db/"]
        print(f"{BLUE}[*] Enumerating directories...{RESET}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(requests.get, url + dir_path, timeout=5) for dir_path in common_dirs]
            for future, dir_path in zip(futures, common_dirs):
                try:
                    res = future.result()
                    if res.status_code == 200:
                        print(f"{GREEN}[+] Found: {url + dir_path}{RESET}")
                        logging.info(f"Directory found: {url + dir_path}")
                    elif res.status_code == 403:
                        print(f"{YELLOW}[*] Forbidden: {url + dir_path}{RESET}")
                except requests.RequestException:
                    pass
    except ValueError as e:
        print(f"{RED}[!] Invalid URL: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during enumeration: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def ssl_checker():
    clear_screen()
    print(f"{CYAN}[*] SSL Certificate Checker{RESET}")
    domain = input(f"{YELLOW}Enter domain (e.g., example.com): {RESET}").strip()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"{GREEN}[+] SSL Certificate Details:{RESET}")
                print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
                print(f"Subject: {dict(x[0] for x in cert['subject'])}")
                print(f"Valid From: {cert['notBefore']}")
                print(f"Valid Until: {cert['notAfter']}")
                expiry = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                if expiry < datetime.now():
                    print(f"{RED}[!] Certificate has expired{RESET}")
                else:
                    print(f"{GREEN}[+] Certificate is valid{RESET}")
                logging.info(f"SSL certificate checked for {domain}")
    except (socket.gaierror, socket.timeout, ssl.SSLError) as e:
        print(f"{RED}[!] Error checking SSL certificate: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def password_generator():
    clear_screen()
    print(f"{CYAN}[*] Password Generator{RESET}")
    length = input(f"{YELLOW}Enter password length (default 12): {RESET}").strip()
    try:
        length = int(length) if length else 12
        if length < 8:
            print(f"{RED}[!] Password length must be at least 8{RESET}")
            return
    except ValueError:
        print(f"{RED}[!] Invalid length{RESET}")
        return
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    print(f"{GREEN}[+] Generated Password:{RESET}\n{password}")
    logging.info(f"Password generated: length {length}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def banner_grabber():
    clear_screen()
    print(f"{CYAN}[*] Banner Grabber{RESET}")
    target = input(f"{YELLOW}Enter target IP or domain: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP or domain{RESET}")
        return
    port = input(f"{YELLOW}Enter port (e.g., 80, 21, 22): {RESET}").strip()
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid port{RESET}")
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target, port))
            if port in [80, 443]:
                s.send(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
            elif port == 21:
                s.send(b"USER anonymous\r\n")
            elif port == 22:
                s.send(b"SSH-2.0-OpenSSH_7.4\r\n")
            else:
                s.send(b"\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            print(f"{GREEN}[+] Banner:{RESET}\n{banner}")
            logging.info(f"Banner grabbed from {target}:{port} - {banner[:100]}...")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
        print(f"{RED}[!] Could not grab banner: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def ip_tracker():
    clear_screen()
    print(f"{CYAN}[*] IP Geolocation Tracker{RESET}")
    ip = input(f"{YELLOW}Enter IP address: {RESET}").strip()
    if not validate_ip_or_domain(ip):
        print(f"{RED}[!] Invalid IP address{RESET}")
        return
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        response.raise_for_status()
        data = response.json()
        if 'error' in data:
            raise ValueError(data.get('reason', 'Unknown error'))
        print(f"{GREEN}[+] Geolocation Data:{RESET}")
        print(f"IP: {data.get('ip')}")
        print(f"City: {data.get('city')}")
        print(f"Region: {data.get('region')}")
        print(f"Country: {data.get('country_name')}")
        print(f"Latitude: {data.get('latitude')}")
        print(f"Longitude: {data.get('longitude')}")
        print(f"ISP: {data.get('org')}")
        logging.info(f"IP lookup for {ip}: {data.get('city')}, {data.get('country_name')}")
    except (requests.RequestException, ValueError) as e:
        print(f"{RED}[!] Error fetching geolocation data: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def ip_logger():
    clear_screen()
    print(f"{CYAN}[*] Activity Logger{RESET}")
    print(f"{YELLOW}[*] Reading logged activities from cyber_defense_log.txt{RESET}")
    try:
        with open('cyber_defense_log.txt', 'r', encoding='utf-8') as f:
            logs = f.readlines()
        if not logs:
            print(f"{RED}[!] No logged activities found{RESET}")
        else:
            print(f"{GREEN}[+] Logged Activities (Last 50):{RESET}")
            for log in logs[-50:]:
                print(log.strip())
    except FileNotFoundError:
        print(f"{RED}[!] Log file not found{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error reading log: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def packet_sniffer():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Packet Sniffer{RESET}")
    print(f"{YELLOW}[!] Requires administrator/root privileges{RESET}")
    interface = input(f"{YELLOW}Enter network interface (e.g., eth0, wlan0): {RESET}").strip()
    count = input(f"{YELLOW}Enter number of packets to capture (default 10): {RESET}").strip()
    try:
        count = int(count) if count else 10
        if count <= 0:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid packet count{RESET}")
        return
    def process_packet(packet):
        try:
            print(f"{GREEN}[+] Packet: {packet.summary()}{RESET}")
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                print(f"Source: {src} -> Destination: {dst} | Protocol: {proto}")
            logging.debug(f"Packet captured on {interface}: {packet.summary()}")
        except Exception as e:
            logging.debug(f"Packet processing error: {str(e)}")
    try:
        print(f"{BLUE}[*] Sniffing {count} packets on {interface}... (Ctrl+C to stop){RESET}")
        sniff(iface=interface, prn=process_packet, count=count, store=0)
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied or invalid interface: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Sniffing stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error sniffing packets: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def sql_injection_tester():
    clear_screen()
    print(f"{CYAN}[*] SQL Injection Tester{RESET}")
    url = input(f"{YELLOW}Enter URL (e.g., http://example.com/page?id=1): {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    payloads = [
        "' OR '1'='1", "' OR '1'='1' --", "1; DROP TABLE users --",
        "' UNION SELECT 1,2,3 --", "' OR 'a'='a", "1' ORDER BY 1--",
        "' AND 1=0 UNION ALL SELECT @@version --"
    ]
    error_patterns = ['sql', 'mysql', 'syntax error', 'database', 'sqlite', 'postgresql']
    print(f"{BLUE}[*] Testing SQL injection vulnerabilities...{RESET}")
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        for payload in payloads:
            test_url = url + payload
            try:
                res = requests.get(test_url, timeout=5)
                if any(pat in res.text.lower() for pat in error_patterns) or res.status_code == 500:
                    print(f"{YELLOW}[!] Potential SQLi with payload: {payload}{RESET}")
                    logging.info(f"Potential SQLi found at {url} with payload: {payload}")
                else:
                    print(f"{GREEN}[+] No vulnerability detected with payload: {payload}{RESET}")
            except requests.RequestException as e:
                print(f"{RED}[!] Error testing payload {payload}: {str(e)}{RESET}")
    except ValueError as e:
        print(f"{RED}[!] Invalid URL: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during testing: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def network_traffic_analysis():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Network Traffic Analysis{RESET}")
    print(f"{YELLOW}[!] Requires administrator/root privileges{RESET}")
    interface = input(f"{YELLOW}Enter network interface (e.g., eth0, wlan0): {RESET}").strip()
    duration = input(f"{YELLOW}Enter duration in seconds (default 30): {RESET}").strip()
    try:
        duration = int(duration) if duration else 30
        if duration <= 0:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid duration{RESET}")
        return
    protocols = {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
    ip_counts = {}
    def process_packet(packet):
        try:
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                src = packet[scapy.IP].src
                ip_counts[src] = ip_counts.get(src, 0) + 1
                if proto == 6:
                    protocols['tcp'] += 1
                elif proto == 17:
                    protocols['udp'] += 1
                elif proto == 1:
                    protocols['icmp'] += 1
                else:
                    protocols['other'] += 1
                print(f"[*] Packet: {packet.summary()}")
                logging.debug(f"Traffic analyzed: {src} -> {packet.summary()}")
        except Exception as e:
            logging.debug(f"Packet processing error: {str(e)}")
    try:
        print(f"{BLUE}[*] Analyzing traffic on {interface} for {duration}s...{RESET}")
        sniff(iface=interface, prn=process_packet, timeout=duration, store=0)
        print(f"{GREEN}\n[+] Traffic Analysis Summary:{RESET}")
        print("Protocol Distribution:")
        for proto, count in protocols.items():
            print(f"{proto.upper()}: {count} packets")
        print("\nTop 5 Source IPs:")
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"{ip}: {count} packets")
        logging.info(f"Traffic analysis completed on {interface}: {protocols}")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Analysis stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during analysis: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def vulnerability_scanner():
    clear_screen()
    print(f"{CYAN}[*] Vulnerability Scanner{RESET}")
    target = input(f"{YELLOW}Enter target IP or domain: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP or domain{RESET}")
        return
    ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389]
    open_services = {}
    print(f"{BLUE}[*] Scanning for open services...{RESET}")
    try:
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "UNKNOWN"
                    open_services[port] = service
                    print(f"{GREEN}[+] {service} open on port {port}{RESET}")
        if not open_services:
            print(f"{RED}[!] No open services found{RESET}")
            input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")
            return
        print(f"{BLUE}[*] Checking for known vulnerabilities...{RESET}")
        cve_db = {
            'ftp': ['CVE-2019-1234'], 'ssh': ['CVE-2020-5678'],
            'telnet': ['CVE-2017-9012'], 'http': ['CVE-2021-41773'],
            'https': ['CVE-2021-41773'], 'smb': ['CVE-2020-0796'],
            'mysql': ['CVE-2020-14812'], 'mssql': ['CVE-2019-1068'],
            'rdp': ['CVE-2019-0708']
        }
        for port, service in open_services.items():
            service_key = service.lower()
            if service_key in cve_db:
                print(f"{YELLOW}[!] Potential vulnerability on {service} (port {port}): {cve_db[service_key]}{RESET}")
                logging.info(f"Potential vulnerability on {target}:{port} - {cve_db[service_key]}")
    except Exception as e:
        print(f"{RED}[!] Error during scanning: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def log_analyzer():
    clear_screen()
    print(f"{CYAN}[*] Log Analyzer{RESET}")
    log_file = input(f"{YELLOW}Enter path to log file (e.g., /var/log/auth.log): {RESET}").strip()
    if not os.path.isfile(log_file):
        print(f"{RED}[!] Log file not found{RESET}")
        return
    patterns = {
        'failed_login': r'Failed password for',
        'sql_injection': r'(\%27|\'|\-\-|\%3B|union|select)',
        'brute_force': r'Invalid user.*from',
        'ssh_attack': r'sshd.*Failed',
        'web_attack': r'(GET|POST).*(\.php|\.asp).*(\%27|\')'
    }
    suspicious = []
    print(f"{BLUE}[*] Analyzing log file...{RESET}")
    try:
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                for threat, pattern in patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        suspicious.append((threat, line.strip()))
        if suspicious:
            print(f"{YELLOW}[!] Suspicious activities found:{RESET}")
            for threat, line in suspicious[:20]:
                print(f"{threat}: {line}")
            logging.info(f"Suspicious activity in {log_file}: {len(suspicious)} entries")
        else:
            print(f"{GREEN}[+] No suspicious activities found{RESET}")
    except PermissionError:
        print(f"{RED}[!] Permission denied reading log file{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error analyzing log: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def threat_intelligence():
    clear_screen()
    print(f"{CYAN}[*] Threat Intelligence Feed{RESET}")
    try:
        url = "https://www.spamhaus.org/drop/drop.txt"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        print(f"{GREEN}[+] Recent Threat IPs (Spamhaus DROP List):{RESET}")
        lines = response.text.splitlines()[:10]
        for line in lines:
            if line and not line.startswith(';'):
                print(f"Malicious IP: {line.split()[0]}")
        logging.info(f"Threat intelligence fetched from Spamhaus DROP")
    except requests.RequestException as e:
        print(f"{RED}[!] Error fetching threat data: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Unexpected error: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def firewall_rule_tester():
    clear_screen()
    print(f"{CYAN}[*] Firewall Rule Tester{RESET}")
    target = input(f"{YELLOW}Enter target IP or domain: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP or domain{RESET}")
        return
    common_ports = [22, 80, 443, 3389, 445, 1433, 3306]
    try:
        print(f"{BLUE}[*] Testing firewall rules...{RESET}")
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except OSError:
                            service = "UNKNOWN"
                        print(f"{YELLOW}[!] Port {port} ({service}) is open - Review firewall rules{RESET}")
                        logging.info(f"Open port found in {target}:{port} ({service})")
                    else:
                        print(f"{GREEN}[+] Port {port} is closed{RESET}")
            except Exception as e:
                print(f"{RED}[!] Error testing port {port}: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during firewall test: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def malware_hash_checker():
    clear_screen()
    print(f"{CYAN}[*] Malware Hash Checker{RESET}")
    file_path = input(f"{YELLOW}Enter file path to check: {RESET}").strip()
    if not os.path.isfile(file_path):
        print(f"{RED}[!] File not found{RESET}")
        return
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        print(f"{GREEN}[+] File SHA256 Hash: {file_hash}{RESET}")
        known_malware = ['e99a18c428cb38d5f260853678922e03']
        if file_hash in known_malware:
            print(f"{RED}[!] Warning: File matches known malware hash{RESET}")
            logging.info(f"Malware detected: {file_path} - {file_hash}")
        else:
            print(f"{GREEN}[+] No malware found{RESET}")
    except PermissionError:
        print(f"{RED}[!] Permission denied reading file{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error checking hash: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def arp_spoof_detector():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] ARP Spoofing Detector{RESET}")
    print(f"{YELLOW}[!] Requires root privileges{RESET}")
    interface = input(f"{YELLOW}Enter network interface (e.g., eth0, wlan0): {RESET}").strip()
    duration = input(f"{YELLOW}Enter duration in seconds (default 60): {RESET}").strip()
    try:
        duration = int(duration) if duration else 60
        if duration <= 0:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid duration{RESET}")
        return
    arp_table = {}
    def process_packet(packet):
        try:
            if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
                mac = packet[ARP].hwsrc
                ip = packet[ARP].psrc
                if ip in arp_table:
                    if arp_table[ip] != mac:
                        print(f"{RED}[!] ARP Spoofing Detected! IP {ip} changed from {arp_table[ip]} to {mac}{RESET}")
                        logging.info(f"ARP spoofing detected: {ip} from {arp_table[ip]} to {mac}")
                else:
                    arp_table[ip] = mac
        except Exception as e:
            logging.debug(f"ARP packet error: {str(e)}")
    try:
        print(f"{BLUE}[*] Monitoring ARP on {interface} for {duration}s...{RESET}")
        sniff(iface=interface, filter="arp", prn=process_packet, timeout=duration)
        print(f"{GREEN}[+] No ARP spoofing detected{RESET}")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied or invalid interface: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Detection stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during detection: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def web_vulnerability_scanner():
    clear_screen()
    print(f"{CYAN}[*] Web Vulnerability Scanner{RESET}")
    url = input(f"{YELLOW}Enter website URL: {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        print(f"{BLUE}[*] Scanning for vulnerabilities...{RESET}")
        try:
            xss_payload = "<script>alert('XSS')</script>"
            res = requests.get(url + "?q=" + xss_payload, timeout=5)
            if xss_payload in res.text:
                print(f"{YELLOW}[!] Potential XSS vulnerability detected{RESET}")
                logging.info(f"Potential XSS at {url}")
        except requests.RequestException:
            pass
        try:
            res = requests.get(url, timeout=5)
            if not re.search(r'csrf|token', res.text, re.IGNORECASE):
                print(f"{YELLOW}[!] Potential CSRF vulnerability: No CSRF token found{RESET}")
                logging.info(f"Potential CSRF at {url}")
        except requests.RequestException:
            pass
        try:
            res = requests.get(url, timeout=5)
            headers = res.headers
            if 'X-Frame-Options' not in headers:
                print(f"{YELLOW}[!] Missing X-Frame-Options (Clickjacking risk){RESET}")
            if 'Strict-Transport-Security' not in headers:
                print(f"{YELLOW}[!] Missing HSTS header{RESET}")
            logging.info(f"Header scan completed for {url}")
        except requests.RequestException:
            pass
    except ValueError as e:
        print(f"{RED}[!] Invalid URL: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during scan: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def honeypot():
    clear_screen()
    print(f"{CYAN}[*] Honeypot Logger{RESET}")
    print(f"{YELLOW}[!] Simulates a vulnerable service to log attacker attempts{RESET}")
    port = input(f"{YELLOW}Enter port to listen on (e.g., 23): {RESET}").strip()
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid port{RESET}")
        return
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"{BLUE}[*] Honeypot listening on port {port}... (Ctrl+C to stop){RESET}")
        while True:
            client, addr = server.accept()
            print(f"{YELLOW}[!] Connection from {addr[0]}:{addr[1]}{RESET}")
            logging.info(f"Honeypot connection from {addr[0]}:{addr[1]}")
            try:
                data = client.recv(1024).decode('utf-8', errors='ignore')
                print(f"Data: {data[:100]}...")
                client.send(b"Unauthorized access logged\n")
                client.close()
            except Exception:
                client.close()
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Error starting honeypot: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Honeypot stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error in honeypot: {str(e)}{RESET}")
    finally:
        server.close()
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def password_strength():
    clear_screen()
    print(f"{CYAN}[*] Password Strength Analyzer{RESET}")
    password = input(f"{YELLOW}Enter password to analyze: {RESET}").strip()
    if not password:
        print(f"{RED}[!] Empty password{RESET}")
        return
    score = 0
    feedback = []
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters")
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add numbers")
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Add special characters")
    print(f"{GREEN}[+] Password Strength: {'Strong' if score >= 4 else 'Moderate' if score >= 2 else 'Weak'}{RESET}")
    if feedback:
        print(f"{YELLOW}[*] Suggestions:{RESET}")
        for f in feedback:
            print(f"- {f}")
    logging.info(f"Password strength analyzed: score {score}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def intrusion_detection():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Network Intrusion Detection{RESET}")
    print(f"{YELLOW}[!] Requires root privileges{RESET}")
    interface = input(f"{YELLOW}Enter network interface (e.g., eth0, wlan0): {RESET}").strip()
    duration = input(f"{YELLOW}Enter duration in seconds (default 60): {RESET}").strip()
    try:
        duration = int(duration) if duration else 60
        if duration <= 0:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid duration{RESET}")
        return
    ip_counts = {}
    threshold = 100  # Packet threshold
    def process_packet(packet):
        try:
            if packet.haslayer(scapy.IP):
                src = packet[scapy.IP].src
                ip_counts[src] = ip_counts.get(src, 0) + 1
                if ip_counts[src] > threshold:
                    print(f"{RED}[!] Potential intrusion from {src}: {ip_counts[src]} packets{RESET}")
                    logging.info(f"Potential intrusion from {src}: {ip_counts[src]} packets")
        except Exception as e:
            logging.debug(f"Packet processing error: {str(e)}")
    try:
        print(f"{BLUE}[*] Monitoring for intrusions on {interface} for {duration}s...{RESET}")
        sniff(iface=interface, prn=process_packet, timeout=duration, store=0)
        print(f"{GREEN}[+] No intrusions detected{RESET}")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Detection stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during detection: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def file_integrity():
    clear_screen()
    print(f"{CYAN}[*] File Integrity Monitor{RESET}")
    directory = input(f"{YELLOW}Enter directory to monitor: {RESET}").strip()
    if not os.path.isdir(directory):
        print(f"{RED}[!] Directory not found{RESET}")
        return
    baseline_file = 'file_integrity_baseline.json'
    hashes = {}
    def compute_hashes():
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        hashes[file_path] = hashlib.sha256(f.read()).hexdigest()
                except Exception:
                    pass
    try:
        print(f"{BLUE}[*] Creating/Checking baseline...{RESET}")
        if not os.path.exists(baseline_file):
            compute_hashes()
            with open(baseline_file, 'w') as f:
                json.dump(hashes, f)
            print(f"{GREEN}[+] Baseline created{RESET}")
            logging.info(f"File integrity baseline created for {directory}")
        else:
            old_hashes = {}
            with open(baseline_file, 'r') as f:
                old_hashes = json.load(f)
            compute_hashes()
            print(f"{BLUE}[*] Checking for changes...{RESET}")
            for file_path, new_hash in hashes.items():
                if file_path not in old_hashes:
                    print(f"{YELLOW}[!] New file: {file_path}{RESET}")
                    logging.info(f"New file detected: {file_path}")
                elif old_hashes[file_path] != new_hash:
                    print(f"{RED}[!] File modified: {file_path}{RESET}")
                    logging.info(f"File modified: {file_path}")
            for file_path in old_hashes:
                if file_path not in hashes:
                    print(f"{YELLOW}[!] File deleted: {file_path}{RESET}")
                    logging.info(f"File deleted: {file_path}")
            with open(baseline_file, 'w') as f:
                json.dump(hashes, f)
    except Exception as e:
        print(f"{RED}[!] Error during integrity check: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def ddos_detector():
    clear_screen()
    print(f"{CYAN}[*] DDoS Detector{RESET}")
    interface = input(f"{YELLOW}Enter network interface (e.g., eth0, wlan0): {RESET}").strip()
    duration = input(f"{YELLOW}Enter duration in seconds (default 60): {RESET}").strip()
    try:
        duration = int(duration) if duration else 60
        if duration <= 0:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid duration{RESET}")
        return
    packet_count = 0
    start_time = time.time()
    threshold = 1000  # Packets per second
    def process_packet(packet):
        nonlocal packet_count
        packet_count += 1
    try:
        print(f"{BLUE}[*] Monitoring for DDoS on {interface} for {duration}s...{RESET}")
        if scapy:
            sniff(iface=interface, prn=process_packet, timeout=duration, store=0)
        else:
            print(f"{YELLOW}[*] Scapy not available, using CPU monitoring{RESET}")
            while time.time() - start_time < duration:
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 90:
                    print(f"{RED}[!] High CPU usage: {cpu_percent}% - Possible DDoS{RESET}")
                    logging.info(f"High CPU usage: {cpu_percent}%")
        elapsed = time.time() - start_time
        pps = packet_count / elapsed
        if pps > threshold:
            print(f"{RED}[!] Potential DDoS: {pps:.2f} packets/sec{RESET}")
            logging.info(f"Potential DDoS: {pps:.2f} packets/sec")
        else:
            print(f"{GREEN}[+] No DDoS detected: {pps:.2f} packets/sec{RESET}")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Detection stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during detection: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def phishing_url_detector():
    clear_screen()
    print(f"{CYAN}[*] Phishing URL Detector{RESET}")
    url = input(f"{YELLOW}Enter URL to analyze: {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL")
        print(f"{BLUE}[*] Analyzing URL...{RESET}")
        score = 0
        feedback = []
        if any(c in parsed.netloc for c in ['-', '_', '@']):
            score += 1
            feedback.append("Suspicious characters in domain")
        if len(parsed.netloc) > 30:
            score += 1
            feedback.append("Unusually long domain")
        if parsed.scheme != 'https':
            score += 1
            feedback.append("Non-HTTPS connection")
        if any(kw in url.lower() for kw in ['login', 'secure', 'bank', 'verify']):
            score += 1
            feedback.append("Phishing-related keywords")
        print(f"{GREEN}[+] Result: {'High Risk' if score >= 3 else 'Moderate Risk' if score >= 1 else 'Low Risk'}{RESET}")
        if feedback:
            print(f"{YELLOW}[*] Indicators:{RESET}")
            for f in feedback:
                print(f"- {f}")
        logging.info(f"Phishing URL analysis for {url}: score {score}")
    except ValueError as e:
        print(f"{RED}[!] Invalid URL: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error analyzing URL: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def wifi_scanner():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Wi-Fi Scanner{RESET}")
    print(f"{YELLOW}[!] Requires root privileges and monitor mode{RESET}")
    interface = input(f"{YELLOW}Enter Wi-Fi interface (e.g., wlan0): {RESET}").strip()
    duration = input(f"{YELLOW}Enter duration in seconds (default 20): {RESET}").strip()
    try:
        duration = int(duration) if duration else 20
        if duration <= 0:
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid duration{RESET}")
        return
    networks = {}
    def process_packet(packet):
        try:
            if packet.haslayer(scapy.Dot11Beacon):
                bssid = packet[scapy.Dot11].addr2
                ssid = packet[scapy.Dot11Elt].info.decode('utf-8', errors='ignore')
                if ssid and bssid not in networks:
                    networks[bssid] = ssid
                    print(f"{GREEN}[+] SSID: {ssid} | BSSID: {bssid}{RESET}")
        except Exception as e:
            logging.debug(f"Wi-Fi packet error: {str(e)}")
    try:
        print(f"{BLUE}[*] Scanning Wi-Fi networks on {interface}...{RESET}")
        sniff(iface=interface, prn=process_packet, timeout=duration, store=0)
        print(f"{GREEN}[+] Found {len(networks)} networks{RESET}")
        logging.info(f"Wi-Fi scan completed on {interface}: {len(networks)} networks")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Error: Permission denied or invalid interface: {str(e)}{RESET}")
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error scanning Wi-Fi: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def service_fingerprint():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Service Fingerprinting{RESET}")
    target = input(f"{YELLOW}Enter target IP: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP or domain{RESET}")
        return
    port = input(f"{YELLOW}Enter port (e.g., 80, 22): {RESET}").strip()
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        print(f"{RED}[!] Invalid port{RESET}")
        return
    try:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12:  # SYN-ACK
            print(f"{GREEN}[+] Service open on {target}:{port}{RESET}")
            if port == 80 or port == 443:
                try:
                    res = requests.get(f"http{'s' if port == 443 else ''}://{target}", timeout=5)
                    server = res.headers.get('Server', 'Unknown')
                    print(f"Server: {server}")
                    logging.info(f"Service fingerprint: {target}:{port} -> {server}")
                except requests.RequestException:
                    print(f"{YELLOW}[*] No server in HTTP headers{RESET}")
            elif port == 22:
                print(f"Possible SSH service")
                logging.info(f"Service fingerprint: {target}:{port} -> SSH")
        else:
            print(f"{RED}[!] Port {port} closed or filtered{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error fingerprinting: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def brute_force_detector():
    clear_screen()
    print(f"{CYAN}[*] Brute Force Detector{RESET}")
    log_file = input(f"{YELLOW}Enter log file path (e.g., /var/log/auth.log): {RESET}").strip()
    if not os.path.isfile(log_file):
        print(f"{RED}[!] File not found{RESET}")
        return
    threshold = 5
    time_window = 60  # seconds
    attempts = {}
    try:
        print(f"{BLUE}[*] Analyzing log for brute-force attempts...{RESET}")
        with open(log_file, 'r', errors='ignore') as f:
            for line in f:
                if re.search(r'Failed password', line, re.IGNORECASE):
                    match = re.search(r'from (\S+)', line)
                    if match:
                        ip = match.group(1)
                        timestamp = time.time()
                        attempts[ip] = attempts.get(ip, [])
                        attempts[ip].append(timestamp)
                        attempts[ip] = [t for t in attempts[ip] if t >= timestamp - time_window]
                        if len(attempts[ip]) >= threshold:
                            print(f"{RED}[!] Brute-force attempt from {ip}: {len(attempts[ip])} attempts{RESET}")
                            logging.info(f"Brute-force from {ip}: {len(attempts[ip])} attempts")
        print(f"{GREEN}[+] Analysis complete{RESET}")
    except PermissionError:
        print(f"{RED}[!] Permission denied reading log{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error analyzing log: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def network_map():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Network Mapping{RESET}")
    print(f"{YELLOW}[!] Requires root privileges{RESET}")
    subnet = input(f"{YELLOW}Enter subnet (e.g., 192.168.1.0/24): {RESET}").strip()
    try:
        print(f"{BLUE}[*] Mapping network...{RESET}")
        ans, _ = scapy.arping(subnet, timeout=2, verbose=0)
        print(f"{GREEN}[+] Devices found:{RESET}")
        for pkt in ans:
            ip = pkt[1][scapy.IP].src
            mac = pkt[1][scapy.ARP].hwsrc
            print(f"IP: {ip} | MAC: {mac}")
            logging.info(f"Network map: {ip} -> {mac}")
        print(f"{GREEN}[+] Mapping complete{RESET}")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error mapping network: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def packet_injection_tester():
    if not scapy:
        print(f"{RED}[!] Scapy not installed. Install with: pip install scapy{RESET}")
        return
    clear_screen()
    print(f"{CYAN}[*] Packet Injection Tester{RESET}")
    print(f"{YELLOW}[!] Requires root privileges{RESET}")
    interface = input(f"{YELLOW}Enter network interface (e.g., eth0, wlan0): {RESET}").strip()
    target = input(f"{YELLOW}Enter target IP: {RESET}").strip()
    if not validate_ip_or_domain(target):
        print(f"{RED}[!] Invalid IP{RESET}")
        return
    try:
        pkt = IP(dst=target)/ICMP()
        print(f"{BLUE}[*] Sending test ICMP packet to {target}...{RESET}")
        resp = scapy.sr1(pkt, iface=interface, timeout=2, verbose=0)
        if resp:
            print(f"{GREEN}[+] Response received from {target}: {resp.summary()}{RESET}")
            logging.info(f"Packet injection test successful: {target}")
        else:
            print(f"{RED}[!] No response received{RESET}")
    except (PermissionError, OSError) as e:
        print(f"{RED}[!] Permission denied: {str(e)}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error during injection test: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")

def web_crawler():
    clear_screen()
    print(f"{CYAN}[*] Web Crawler{RESET}")
    url = input(f"{YELLOW}Enter starting URL: {RESET}").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    max_depth = 2
    visited = set()
    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return
        visited.add(url)
        try:
            res = requests.get(url, timeout=3)
            res.raise_for_status()
            print(f"{GREEN}[+] Found: {url}{RESET}")
            logging.info(f"Crawled: {url}")
            soup = re.findall(r'href=[\'"]?([^\'" >]+)', res.text)
            for link in soup:
                next_url = urlparse.urljoin(url, link)
                if urlparse(next_url).netloc == urlparse(url).netloc:
                    crawl(next_url, depth + 1)
        except Exception:
            pass
    try:
        print(f"{BLUE}[*] Crawling {url}...{RESET}")
        crawl(url, 0)
        print(f"{GREEN}[+] Crawling complete: {len(visited)} pages found{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error crawling: {str(e)}{RESET}")
    input(f"\n{GREEN}[*] Press Enter to continue...{RESET}")


# Color Constants
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Menu Structure
MENU_CATEGORIES = [
    {
        "name": "1️⃣ Network Analysis",
        "emoji": "🛰️",
        "tools": [
            ("Port Scanner", "port_scanner"),
            ("Traceroute", "traceroute"),
            ("Subdomain Scanner", "subdomain_scanner"),
            ("Network Mapping", "network_map"),
            ("Packet Sniffer", "packet_sniffer"),
            ("Wi-Fi Scanner", "wifi_scanner"),
            ("ARP Spoof Detector", "arp_spoof_detector")
        ]
    },
    {
        "name": "2️⃣ Web Tools",
        "emoji": "🌐",
        "tools": [
            ("WHOIS Lookup", "whois_lookup"),
            ("DNS Lookup", "dns_lookup"),
            ("HTTP Headers", "http_headers"),
            ("robots.txt Scanner", "robots_scanner"),
            ("Web Crawler", "web_crawler"),
            ("SSL Checker", "ssl_checker"),
            ("Web Vuln Scanner", "web_vulnerability_scanner")
        ]
    },
    {
        "name": "3️⃣ Reconnaissance",
        "emoji": "🔍",
        "tools": [
            ("Google Dork Gen", "google_dork"),
            ("IP Geolocation", "ip_tracker"),
            ("Banner Grabber", "banner_grabber"),
            ("Service Fingerprint", "service_fingerprint"),
            ("Directory Enum", "directory_enumeration"),
            ("Threat Intel Feed", "threat_intelligence")
        ]
    },
    {
        "name": "4️⃣ Security Testing",
        "emoji": "🛡️",
        "tools": [
            ("Vulnerability Scan", "vulnerability_scanner"),
            ("SQLi Tester", "sql_injection_tester"),
            ("Payload Generator", "payload_generator"),
            ("Firewall Tester", "firewall_rule_tester"),
            ("Phishing URL Detect", "phishing_url_detector"),
            ("DDoS Detector", "ddos_detector")
        ]
    },
    {
        "name": "5️⃣ Crypto Tools",
        "emoji": "🔐",
        "tools": [
            ("Hash Cracker", "hash_cracker"),
            ("Password Generator", "password_generator"),
            ("Password Analyzer", "password_strength"),
            ("Malware Hash Check", "malware_hash_checker")
        ]
    },
    {
        "name": "6️⃣ Monitoring",
        "emoji": "📊",
        "tools": [
            ("Network Traffic", "network_traffic_analysis"),
            ("Log Analyzer", "log_analyzer"),
            ("File Integrity", "file_integrity"),
            ("Intrusion Detection", "intrusion_detection"),
            ("Brute Force Detect", "brute_force_detector"),
            ("Honeypot Logger", "honeypot")
        ]
    }
]

def clear_screen():
    """Clear the terminal screen"""
    print("\033[H\033[J", end="")

def check_requirements():
    """Check system requirements"""
    # Add your requirement checks here
    return True

def display_header():
    """Show the tool header/banner"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}")
    print("████████╗██╗░░██╗░█████╗░██╗░░░░░░█████╗░██████╗░██╗███████╗███╗░░██╗")
    print("╚══██╔══╝██║░░██║██╔══██╗██║░░░░░██╔══██╗██╔══██╗██║██╔════╝████╗░██║")
    print("░░░██║░░░███████║███████║██║░░░░░██║░░██║██████╔╝██║█████╗░░██╔██╗██║")
    print("░░░██║░░░██╔══██║██╔══██║██║░░░░░██║░░██║██╔══██╗██║██╔══╝░░██║╚████║")
    print("░░░██║░░░██║░░██║██║░░██║███████╗╚█████╔╝██║░░██║██║███████╗██║░╚███║")
    print(f"░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚══════╝░╚════╝░╚═╝░░╚═╝╚═╝╚══════╝╚═╝░░╚══╝ {Colors.RESET}")
    print(f"{Colors.GRAY}Advanced Cybersecurity Toolkit - by Rifat{Colors.RESET}")
    print(f"{Colors.GRAY}────────────────────────────────────────────{Colors.RESET}")

def display_category_page(page_num):
    """Display one category per page"""
    category = MENU_CATEGORIES[page_num - 1]
    tool_map = {}
    
    print(f"\n{Colors.CYAN}{category['emoji']} {category['name']} {Colors.GRAY}{'─'*(35-len(category['name']))}{Colors.RESET}")
    
    current_number = 1
    for tool in category['tools']:
        tool_name, tool_func = tool
        print(f" {Colors.YELLOW}{current_number:2d}.{Colors.RESET} {tool_name}")
        tool_map[str(current_number)] = tool_func
        current_number += 1
    
    print(f"\n{Colors.GRAY}────────────────────────────────────────────{Colors.RESET}")
    print(f" {Colors.YELLOW} N.{Colors.RESET} Next Category")
    print(f" {Colors.YELLOW} P.{Colors.RESET} Previous Category")
    print(f" {Colors.YELLOW} 0.{Colors.RESET} Main Menu")
    print(f"{Colors.GRAY}────────────────────────────────────────────{Colors.RESET}")
    
    return tool_map

def main_menu():
    if not check_requirements():
        return
    
    current_page = 1
    total_pages = len(MENU_CATEGORIES)
    
    while True:
        clear_screen()
        display_header()
        
        print(f"\n{Colors.WHITE}{Colors.BOLD}CATEGORIES:{Colors.RESET}")
        for i, cat in enumerate(MENU_CATEGORIES, 1):
            prefix = ">" if i == current_page else " "
            print(f" {prefix} {cat['emoji']} {cat['name'][3:]}")
        
        print(f"\n{Colors.GRAY}────────────────────────────────────────────{Colors.RESET}")
        choice = input(f"{Colors.YELLOW}[?] Select category (1-{total_pages}) or 0 to exit: {Colors.RESET}").strip().lower()
        
        if choice == "0":
            print(f"\n{Colors.GREEN}[+] Exiting... Goodbye!{Colors.RESET}")
            sys.exit(0)
        
        if choice.isdigit() and 1 <= int(choice) <= total_pages:
            current_page = int(choice)
            category_loop(current_page)
        else:
            print(f"{Colors.RED}[!] Invalid selection{Colors.RESET}")
            time.sleep(0.5)

def category_loop(page_num):
    """Handle navigation within a category"""
    while True:
        clear_screen()
        display_header()
        tool_map = display_category_page(page_num)
        
        choice = input(f"\n{Colors.YELLOW}[?] Select tool or navigation: {Colors.RESET}").strip().lower()
        
        if choice == "n":
            return min(page_num + 1, len(MENU_CATEGORIES))
        elif choice == "p":
            return max(page_num - 1, 1)
        elif choice == "0":
            return page_num
        elif choice in tool_map:
            try:
                globals()[tool_map[choice]]()
                input(f"\n{Colors.GREEN}[+] Press Enter to continue...{Colors.RESET}")
            except KeyError:
                print(f"{Colors.RED}[!] Tool not implemented yet{Colors.RESET}")
                time.sleep(1)
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
                time.sleep(2)
        else:
            print(f"{Colors.RED}[!] Invalid selection{Colors.RESET}")
            time.sleep(0.5)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
        sys.exit(1)