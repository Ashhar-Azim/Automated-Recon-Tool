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
import logging

# Configure the logging
logging.basicConfig(filename="recon_log.txt", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_and_print(message, level=logging.INFO):
    """
    Log a message and print it to the console with extensive error handling.
    :param message: The message to log and print.
    :param level: The logging level (default is INFO).
    """
    try:
        logging.log(level, message)
        print(message)
    except Exception as e:
        print(f"An error occurred while logging and printing the message: {str(e)}")

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        log_and_print(f"Error: {e}", level=logging.ERROR)
        return None
    except socket.error as e:
        log_and_print(f"Socket error: {e}", level=logging.ERROR)
        return None
    except Exception as e:
        log_and_print(f"An unexpected error occurred: {e}", level=logging.ERROR)
        return None

def xmas_scan(ip_address, start_port, end_port):
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            src_port = RandShort()
            response = sr1(IP(dst=ip_address) / TCP(sport=src_port, dport=port, flags="FPU"), timeout=2, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags == 0x14:
                open_ports.append(port)
    except PermissionError as e:
        log_and_print(f"Permission error: {e}", level=logging.ERROR)
    except Scapy_Exception as e:
        log_and_print(f"Scapy error: {e}", level=logging.ERROR)
    except Exception as e:
        log_and_print(f"An unexpected error occurred: {e}", level=logging.ERROR)

    return open_ports

def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except whois.parser.PywhoisError as e:
        log_and_print(f"WHOIS error: {e}", level=logging.ERROR)
        return f"WHOIS error: {e}"
    except Exception as e:
        log_and_print(f"An unexpected error occurred: {e}", level=logging.ERROR)
        return f"An unexpected error occurred: {e}"

def banner_grabbing(ip_address, ports):
    banners = {}
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip_address, port))
                banner = sock.recv(1024).decode()
                banners[port] = banner
        except socket.timeout:
            banners[port] = f"Error: Connection to port {port} timed out."
        except ConnectionRefusedError:
            banners[port] = f"Error: Connection to port {port} was refused."
        except OSError as e:
            banners[port] = f"Error: {str(e)}"
        except Exception as e:
            banners[port] = f"An unexpected error occurred for port {port}: {str(e)}"
    return banners

def dns_enumeration(domain):
    try:
        answers = dns.resolver.query(domain, 'A')
        ip_addresses = [r.address for r in answers]
        return ip_addresses
    except dns.resolver.NXDOMAIN:
        log_and_print(f"Error: The domain '{domain}' does not exist (NXDOMAIN).", level=logging.ERROR)
        return f"Error: The domain '{domain}' does not exist (NXDOMAIN)."
    except dns.exception.DNSException as e:
        log_and_print(f"DNS query for '{domain}' failed with error: {e}", level=logging.ERROR)
        return f"DNS query for '{domain}' failed with error: {e}"
    except Exception as e:
        log_and_print(f"An unexpected error occurred for domain '{domain}': {str(e}", level=logging.ERROR)
        return f"An unexpected error occurred for domain '{domain}': {str(e)}"

def get_geolocation(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx and 5xx)
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        log_and_print(f"Error: {str(e)}", level=logging.ERROR)
        return f"Error: {str(e)}"
    except requests.exceptions.HTTPError as e:
        log_and_print(f"HTTP error: {str(e)}", level=logging.ERROR)
        return f"HTTP error: {str(e)}"
    except ValueError as e:
        log_and_print(f"Error parsing JSON response: {str(e)}", level=logging.ERROR)
        return f"Error parsing JSON response: {str(e)}"
    except Exception as e:
        log_and_print(f"An unexpected error occurred: {str(e)}", level=logging.ERROR)
        return f"An unexpected error occurred: {str(e)}"

def create_network_map(ip_addresses, open_ports):
    if not ip_addresses:
        log_and_print("No IP addresses provided. Cannot create a network map.", level=logging.WARNING)
        print("No IP addresses provided. Cannot create a network map.")
        return None
    if not open_ports:
        log_and_print("No open ports provided. The network map will not contain service nodes.", level=logging.INFO)
        print("No open ports provided. The network map will not contain service nodes.")
    G = nx.Graph()

    for ip in ip_addresses:
        G.add_node(ip, type='host')
        if open_ports:
            for port in open_ports:
                G.add_node(f"{ip}:{port}", type='service')
                G.add_edge(ip, f"{ip}:{port}")

    return G

def plot_network_map(G):
    if G is None:
        log_and_print("The network map is empty. Cannot plot.", level=logging.WARNING)
        print("The network map is empty. Cannot plot.")
        return

    try:
        pos = nx.spring_layout(G)
        node_types = [G.nodes[n]['type'] for n in G.nodes]

        nx.draw_networkx_nodes(G, pos, node_size=500, node_color='lightblue', nodelist=[n for n, t in zip(G.nodes, node_types) if t == 'host'])
        nx.draw_networkx_nodes(G, pos, node_size=300, node_color='orange', nodelist=[n for n, t in zip(G.nodes, node_types) if t == 'service'])
        nx.draw_networkx_labels(G, pos)
        nx.draw_networkx_edges(G, pos, width=1, edge_color='gray')
        plt.axis('off')
        plt.show()
    except Exception as e:
        log_and_print(f"An error occurred while plotting the network map: {str(e)}", level=logging.ERROR)
        print(f"An error occurred while plotting the network map: {str(e)}")

def save_results(results, format):
    try:
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
                htmlfile.write(html.escape(json.dumps(results, indent=4))
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
        else:
            log_and_print(f"Unsupported format: {format}. Results were not saved.", level=logging.WARNING)
            print(f"Unsupported format: {format}. Results were not saved.")
    except Exception as e:
        log_and_print(f"An error occurred while saving results: {str(e)}", level=logging.ERROR)
        print(f"An error occurred while saving results: {str(e)}")

# DRIVER CODE
if __name__ == "__main__":
    target_domain = input("Enter the target domain or IP address: ")
    target_ip = get_ip_address(target_domain)

    if target_ip:
        log_and_print(f"Scanning {target_domain} ({target_ip})")

        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port:"))

        xmas_open_ports = xmas_scan(target_ip, start_port, end_port)

        log_and_print("XMAS Scanning Results:", level=logging.INFO)
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
            log_and_print("Failed to retrieve WHOIS information", level=logging.ERROR)
            print("Failed to retrieve WHOIS information")

        dns_results = dns_enumeration(target_domain)
        if dns_results:
            print("\nDNS Enumeration:")
            for ip in dns_results:
                print(f"{target_domain} resolves to {ip}")
        else:
            log_and_print(f"No DNS records found for {target_domain}", level=logging.WARNING)
            print(f"No DNS records found for {target_domain}")

        geolocation_info = get_geolocation(target_ip)
        if geolocation_info:
            print("\nGeolocation Information:")
            for key, value in geolocation_info.items():
                print(f"{key}: {value}")
        else:
            log_and_print("Failed to retrieve geolocation information.", level=logging.ERROR)
            print("Failed to retrieve geolocation information.")

        network_map = create_network_map([target_ip] + dns_results, xmas_open_ports)
        plot_network_map(network_map)

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
        log_and_print(f"Results saved in {save_format} format.", level=logging.INFO)
    else:
        log_and_print("Invalid domain or IP address", level=logging.ERROR)

