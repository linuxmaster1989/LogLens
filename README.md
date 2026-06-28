"""
================================================================================
LogLens Threat Analyzer - README
================================================================================
LogLens is an automated security tool for scanning system/web logs to identify 
and block malicious IP addresses.

1. Setup:
   Ensure 'auth.log' and 'access.log' are in the same folder as this script.
   Install dependencies: pip install dnspython ipwhois

2. Usage:
   Run: python3 main.py
   Select Option 1 (SSH) or Option 2 (Web) from the menu.

3. Defense:
   The script will generate 'Batch' commands. Copy and paste these into your 
   terminal to update your UFW firewall.

4. Maintenance:
   Reset system logs: sudo truncate -s 0 /var/log/auth.log
================================================================================
"""

import re
import os
import socket

# File paths in current directory
AUTH_LOG = "auth.log"
WEB_ACCESS_LOG = "access.log"

def get_dns_report(ip):
    try:
        data = socket.gethostbyaddr(ip)
        return data[0]
    except:
        return "No PTR record found"

def generate_block_commands(ips):
    if not ips:
        print("\nNo new attackers found to block.")
        return
    print("\n>>> COPY AND PASTE THESE COMMANDS TO BLOCK ATTACKERS:")
    chunk_size = 10
    chunks = [list(ips)[i:i + chunk_size] for i in range(0, len(ips), chunk_size)]
    for idx, chunk in enumerate(chunks):
        ip_list = " ".join(chunk)
        print(f"\n--- Batch {idx + 1} ---")
        print(f"for ip in {ip_list}; do sudo ufw deny from $ip; done")

def scan_auth():
    print("\n--- Scanning Auth Logs ---")
    pattern = re.compile(r"(?:Invalid user|authenticating user) (\S+)(?: from)? (\d+\.\d+\.\d+\.\d+)")
    attackers = {}
    if not os.path.exists(AUTH_LOG):
        print(f"Error: '{AUTH_LOG}' not found.")
        return
    with open(AUTH_LOG, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match: attackers[match.group(2)] = True
    for ip in attackers:
        print(f"Detected: {ip} | Host: {get_dns_report(ip)}")
    generate_block_commands(attackers.keys())

def scan_access():
    print("\n--- Scanning Web Access Logs ---")
    pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    attackers = set()
    if not os.path.exists(WEB_ACCESS_LOG):
        print(f"Error: '{WEB_ACCESS_LOG}' not found.")
        return
    with open(WEB_ACCESS_LOG, "r") as f:
        for line in f:
            if any(code in line for code in [" 404 ", " 403 ", " 400 "]):
                match = pattern.search(line)
                if match: attackers.add(match.group(1))
    for ip in attackers:
        print(f"Detected Probe: {ip} | Host: {get_dns_report(ip)}")
    generate_block_commands(attackers)

if __name__ == "__main__":
    while True:
        print("\n========================================")
        print("        LogLens - Threat Analyzer       ")
        print("========================================")
        print("1. Scan auth.log (SSH)")
        print("2. Scan access.log (Web)")
        print("3. Exit")
        choice = input("\nSelect an option (1-3): ")
        if choice == '1': scan_auth()
        elif choice == '2': scan_access()
        elif choice == '3': break
        else: print("Invalid selection.")
        
