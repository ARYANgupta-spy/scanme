import socket
import threading
from queue import Queue
import time
import requests

# Common port to service mapping
common_ports = {
    80: "http",
    443: "https",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    110: "pop3",
    143: "imap"
}

# Function to fetch vulnerability data (simulated)
def fetch_vulnerabilities(service):
    vulnerabilities = {
        "http": ["SQL Injection", "XSS", "Directory Traversal"],
        "https": ["Weak TLS Configurations", "Man-in-the-Middle Risks"],
        "ftp": ["Anonymous Login", "Command Injection"],
        "ssh": ["Weak Passwords", "SSH Key Vulnerabilities"],
        "smtp": ["Open Relay", "Spoofing"],
        "pop3": ["Plaintext Authentication", "Data Leakage"],
        "imap": ["Plaintext Authentication", "Command Injection"]
    }
    return vulnerabilities.get(service.lower(), [])

# Resolve domain to IP address
def resolve_domain_to_ip(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved domain {host} to IP: {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Unable to resolve domain name {host}")
        return None

# Check if a port is open
def check_port(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=2)
        sock.close()
        return True
    except socket.error:
        return False

# Port scanning worker
def port_scan_worker(ip, queue, results):
    while not queue.empty():
        port = queue.get()
        if check_port(ip, port):
            service_name = common_ports.get(port, socket.getservbyport(port, "tcp"))
            vulns = fetch_vulnerabilities(service_name) if service_name else []
            results.append((port, service_name, vulns, True))
        else:
            results.append((port, None, None, False))
        queue.task_done()

# Main scanning function
def scan_host(ip, ports):
    queue = Queue()
    results = []
    threads = []

    # Add ports to the queue
    for port in ports:
        queue.put(port)

    # Start threads
    for _ in range(10):  # Number of threads
        thread = threading.Thread(target=port_scan_worker, args=(ip, queue, results))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Filter and display results
    for port, service, vulns, is_open in sorted(results):
        if is_open:
            print(f"[+] Port {port} (Service: {service}) is OPEN.")
            if vulns:
                print(f"  Detected vulnerabilities for {service.upper()} on port {port}:")
                for vuln in vulns:
                    print(f"  - {vuln}")
            else:
                print(f"  No significant vulnerabilities detected for {service.upper()} on port {port}.")
        else:
            print(f"[-] Port {port} is closed or unreachable.")

# Validate IP address
def is_valid_ip(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

# Collect user inputs
host = input("Enter the target IP address or domain name: ")
description = input("Provide a description or purpose of this scan: ")

# Resolve IP
ip_address = resolve_domain_to_ip(host) if not is_valid_ip(host) else host
if not ip_address:
    print("Exiting: Invalid IP or domain.")
    exit()

# Port scan choice
print("Choose an option for port scanning:")
print("1. Specify a range of ports (e.g., 20-1000)")
print("2. Enter specific ports manually (comma-separated, e.g., 22,80,443)")
print("3. Scan all ports (1-65535)")

choice = input("Enter your choice (1/2/3): ").strip()

if choice == "1":
    # User specifies a range of ports
    port_range = input("Enter the port range (e.g., 20-1000): ").strip()
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
            ports_to_scan = range(start_port, end_port + 1)
        else:
            raise ValueError
    except ValueError:
        print("Invalid port range. Exiting.")
        exit()
elif choice == "2":
    # User specifies individual ports
    ports = input("Enter ports separated by commas (e.g., 22,80,443): ").strip()
    try:
        ports_to_scan = [int(port) for port in ports.split(",") if 1 <= int(port) <= 65535]
        if not ports_to_scan:
            raise ValueError
    except ValueError:
        print("Invalid port list. Exiting.")
        exit()
elif choice == "3":
    # Scan all ports
    ports_to_scan = range(1, 65536)
else:
    print("Invalid choice. Exiting.")
    exit()

# Begin scanning
print(f"Starting scan on {ip_address}...")
print(f"Scan description: {description}")
start_time = time.time()
scan_host(ip_address, ports_to_scan)
end_time = time.time()

# Print scan duration
print(f"\nScan completed in {end_time - start_time:.2f} seconds.")
