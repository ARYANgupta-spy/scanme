import socket
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

# Resolve domain to IP address if needed
def resolve_domain_to_ip(host):
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved domain {host} to IP: {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Unable to resolve domain name {host}")
        return None

# Function to check if the port is open
def check_port(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=3)
        sock.close()
        return True
    except socket.error:
        return False

# Vulnerability lookup function based on service name
def lookup_vulnerabilities(service):
    # Sample vulnerability data
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

# Main scanning function
def scan_host(ip, ports):
    for port in ports:
        # Check if the port is open
        if check_port(ip, port):
            service_name = common_ports.get(port, "unknown")
            print(f"[+] Port {port} (Service: {service_name}) is open on {ip}")

            # Lookup vulnerabilities for detected service
            vulns = lookup_vulnerabilities(service_name)
            if vulns:
                print(f"  Detected vulnerabilities for {service_name.upper()} on port {port}:")
                for vuln in vulns:
                    print(f"  - {vuln}")
            else:
                print(f"  No significant vulnerabilities detected for {service_name.upper()} on port {port}.")
        else:
            print(f"[-] Port {port} is closed or unreachable on {ip}.")

# Collect input from the user
host = input("Enter the target IP address or domain name: ")

# Resolve the host to an IP address if it's a domain
ip_address = resolve_domain_to_ip(host) if not host.replace('.', '').isdigit() else host

if ip_address is None:
    print("Exiting: Invalid IP or domain.")
    exit()

# Ports to scan (common ports)
ports_to_scan = list(common_ports.keys())

# Begin scanning
print(f"Starting scan on {ip_address}...")
scan_host(ip_address, ports_to_scan)
