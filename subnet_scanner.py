#subnet_scanner.py
#pythin3 subnet_scanner.py

import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# List of common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]

def scan_port(ip, port):
    """Scan a single port on a given IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Set a timeout for the connection attempt
        result = sock.connect_ex((ip, port))  # Try to connect to the port
        return result == 0  # Return True if the port is open

def scan_host(ip):
    """Scan common ports on a given host IP address."""
    open_ports = []
    for port in COMMON_PORTS:
        if scan_port(ip, port):
            open_ports.append(port)
    return ip, open_ports

def main(subnet):
    """Scan the specified subnet for open ports."""
    print(f"Scanning subnet: {subnet}")
    active_hosts = []

    # Create a ThreadPoolExecutor to scan multiple hosts concurrently
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_host, str(ip)): ip for ip in ipaddress.IPv4Network(subnet)}
        for future in futures:
            ip, open_ports = future.result()
            if open_ports:
                active_hosts.append((ip, open_ports))

    # Print the results
    for ip, ports in active_hosts:
        print(f"IP: {ip} has open ports: {ports}")

if __name__ == "__main__":
    subnet_input = "192.168.2.0/24"  # Define the subnet to scan
    main(subnet_input)
