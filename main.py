import socket
import whois
import dns.resolver
import requests
from scapy.all import *
import networkx as nx
import matplotlib.pyplot as plt
import csv
import json
import html
import xml.etree.ElementTree as ET

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def xmas_scan(ip_address, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        src_port = RandShort()
        response = sr1(IP(dst=ip_address)/TCP(sport=src_port, dport=port, flags="FPU"), timeout=2, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x14:
            open_ports.append(port)
    return open_ports

def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except whois.parser.PywhoisError as e:
        return str(e)

def banner_grabbing(ip_address, ports):
    banners = {}
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip_address, port))
                banner = sock.recv(1024).decode()
                banners[port] = banner
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            banners[port] = f"Error: {str(e)}"
    return banners

def dns_enumeration(domain):
    try:
        answers = dns.resolver.query(domain, 'A')
        ip_addresses = [r.address for r in answers]
        return ip_addresses
    except dns.resolver.NXDOMAIN:
        return None

def get_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        return data
    except requests.exceptions.RequestException:
        return None

def create_network_map(ip_addresses, open_ports):
    G = nx.Graph()

    for ip in ip_addresses:
        G.add_node(ip, type='host')
        for port in open_ports:
            G.add_node(f"{ip}:{port}", type='service')
            G.add_edge(ip, f"{ip}:{port}")

    return G

def plot_network_map(G):
    pos = nx.spring_layout(G)
    node_types = [G.nodes[n]['type'] for n in G.nodes]

    nx.draw_networkx_nodes(G, pos, node_size=500, node_color='lightblue', nodelist=[n for n, t in zip(G.nodes, node_types) if t == 'host'])
    nx.draw_networkx_nodes(G, pos, node_size=300, node_color='orange', nodelist=[n for n, t in zip(G.nodes, node_types) if t == 'service'])
    nx.draw_networkx_labels(G, pos)
    nx.draw_networkx_edges(G, pos, width=1, edge_color='gray')
    plt.axis('off')
    plt.show()

def save_results(results, format):
    if format == "csv":
        with open("recon_results.csv", 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['IP Address', 'Open Ports', 'Service Banners', 'WHOIS Information', 'DNS Records', 'Geolocation Info'])
            for result in results:
                writer.writerow(result)
    elif format == "json":
        with open("recon_results.json", 'w') as jsonfile:
            json.dump(results, jsonfile, indent=4)
    elif format == "html":
        with open("recon_results.html", 'w') as htmlfile:
            htmlfile.write(html.escape(json.dumps(results, indent=4)))
    elif format == "xml":
        root = ET.Element("ReconResults")
        for result in results:
            entry = ET.SubElement(root, "Entry")
            for key, value in result.items():
                sub_element = ET.SubElement(entry, key)
                sub_element.text = value
        tree = ET.ElementTree(root)
        tree.write("recon_results.xml")
    elif format == "txt":
        with open("recon_results.txt", 'w') as txtfile:
            for result in results:
                for key, value in result.items():
                    txtfile.write(f"{key}: {value}\n")

if __name__ == "__main__":
    target_domain = input("Enter the target domain or IP address: ")
    target_ip = get_ip_address(target_domain)

    if target_ip:
        print(f"Scanning {target_domain} ({target_ip})")

        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port:"))

        xmas_open_ports = xmas_scan(target_ip, start_port, end_port)

        print("XMAS Scanning Results:")
        if xmas_open_ports:
            print(f"Open ports on {target_domain} ({target_ip}): {xmas_open_ports}")
        else:
            print(f"No open ports found on {target_domain} using XMAS scanning.")

        banner_info = banner_grabbing(target_ip, xmas_open_ports)
        print("\nService Banners (XMAS Scanning):")
        for port, banner in banner_info.items():
            print(f"Port {port}: {banner}")

        whois_info = get_whois_info(target_domain)
        if whois_info:
            print("\nWHOIS Information:")
            print(whois_info)
        else:
            print("Failed to retrieve WHOIS information")

        dns_results = dns_enumeration(target_domain)
        if dns_results:
            print("\nDNS Enumeration:")
            for ip in dns_results:
                print(f"{target_domain} resolves to {ip}")
        else:
            print(f"No DNS records found for {target_domain}")

        geolocation_info = get_geolocation(target_ip)
        if geolocation_info:
            print("\nGeolocation Information:")
            for key, value in geolocation_info.items():
                print(f"{key}: {value}")
        else:
            print("Failed to retrieve geolocation information.")
        
        network_map = create_network_map([target_ip] + dns_results, xmas_open_ports)
        plot_network_map(network_map)

        # Collect results for saving
        results = [{
            'IP Address': target_ip,
            'Open Ports': xmas_open_ports,
            'Service Banners': banner_info,
            'WHOIS Information': whois_info,
            'DNS Records': dns_results,
            'Geolocation Info': geolocation_info
        }]

        save_format = input("Select a format to save the results (csv/json/html/xml/txt): ").lower()
        save_results(results, save_format)
    else:
        print("Invalid domain or IP address")



