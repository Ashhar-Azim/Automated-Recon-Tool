import socket
import whois

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def scan_ports(ip_address, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    target_domain = input("Enter the target domain or IP address: ")
    target_ip = get_ip_address(target_domain)

    if target_ip:
        print(f"Scanning {target_domain} ({target_ip})")

        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))

        open_ports = scan_ports(target_ip, start_port, end_port)
        if open_ports:
            print(f"Open ports on {target_domain} ({target_ip}): {open_ports}")
        else:
            print(f"No open ports found on {target_domain} ({target_ip})")

        whois_info = get_whois_info(target_domain)
        if whois_info:
            print("WHOIS Information:")
            print(whois_info)
        else:
            print("Failed to retrieve WHOIS information.")
    else:
        print("Invalid domain or IP address.")
