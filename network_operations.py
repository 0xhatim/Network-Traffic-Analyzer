import pyshark
import argparse
from colorama import Fore, Style, init
from collections import Counter
from datetime import datetime
import logging
import json
import os

class BlueTeamTrafficAnalyzer:
    def __init__(self, live_capture=False, interface=None, file_path=None):
        """
        Initialize the traffic analyzer with either a live capture or a pcap file.
        """
        self.live_capture = live_capture
        self.interface = interface
        self.file_path = file_path
        init(autoreset=True)  # Initialize colorama

        # Set up logging
        logging.basicConfig(filename='detection_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

    def run_analysis(self):
        """
        Run the traffic analysis based on the input mode (live or file).
        """
        print(Fore.GREEN + "Starting traffic analysis...")
        if self.live_capture:
            print(Fore.YELLOW + "Capturing live traffic on interface:", self.interface)
            capture = pyshark.LiveCapture(interface=self.interface)
        else:
            print(Fore.YELLOW + "Analyzing pcap file:", self.file_path)
            capture = pyshark.FileCapture(
                self.file_path,
                display_filter="arp or icmp or dns or tcp or udp",
                only_summaries=True  
            )
        self.analyze_packets(capture)
        capture.close()

    def analyze_packets(self, capture):
        """
        Analyze packets to detect suspicious activities and generate a JSON report.
        """
        # Initialize detection counters and data structures
        nmap_scan_detected = Counter()
        arp_poisoning_detected = set()
        icmp_tunnel_detected = 0
        dns_tunnel_detected = 0
        anomaly_detected = []

        packet_reports = []  # To store detailed reports for each packet

        # Process packets
        for packet in capture:
            packet_info = {
                "packet_number": packet.number,
                "timestamp": packet.sniff_time.isoformat(),
                "protocols": [],
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "detection_details": []  # To store detailed detection information
            }

            try:
                # Check for the IP layer
                if hasattr(packet, 'ip'):
                    ip_version = packet.ip.version

                    # Detect "bogus" IP version
                    if ip_version not in ['4', '6']:
                        detail = f"Detected bogus IP version: {ip_version} in packet {packet.number}"
                        print(Fore.RED + detail)
                        packet_info["detection_details"].append(detail)
                        continue  # Skip further processing for this packet

                    # If IP version is valid, extract IP information
                    packet_info["src_ip"] = packet.ip.src
                    packet_info["dst_ip"] = packet.ip.dst

                # Check for layers and add protocols accordingly
                if hasattr(packet, 'tcp'):
                    self.detect_nmap_scans(packet, nmap_scan_detected, packet_info)
                    packet_info["protocols"].append("TCP")

                elif hasattr(packet, 'udp'):
                    self.detect_udp_scans(packet, nmap_scan_detected, packet_info)
                    packet_info["protocols"].append("UDP")

                # ARP Poisoning Detection
                if hasattr(packet, 'arp'):
                    self.detect_arp_poisoning(packet, arp_poisoning_detected,packet_info)
                    packet_info["protocols"].append("ARP")

                # ICMP Tunneling Detection
                if hasattr(packet, 'icmp'):
                    icmp_tunnel_detected += self.detect_icmp_tunneling(packet,packet_info)
                    packet_info["protocols"].append("ICMP")

                # DNS Tunneling Detection
                if hasattr(packet, 'dns'):
                    dns_tunnel_detected += self.detect_dns_tunneling(packet,packet_info)
                    packet_info["protocols"].append("DNS")

                # Anomaly Detection
                self.detect_anomalies(packet, anomaly_detected,packet_info)
                if len(packet_info['detection_details']) == 0:
                    continue
                # Add packet information to the report
                packet_reports.append(packet_info)

            except AttributeError as e:
                print(f"AttributeError encountered: {e}")
                continue
            except Exception as e:
                print(f"Unexpected error: {e}")
                continue

        self.print_results(nmap_scan_detected, arp_poisoning_detected, icmp_tunnel_detected, dns_tunnel_detected, anomaly_detected)
        self.generate_json_report(packet_reports)

    def detect_nmap_scans(self, packet, nmap_scan_detected, packet_info):
        """
        Detect Nmap scans based on packet analysis.
        """
        # Detect various types of scans by analyzing TCP flags
        if packet.tcp.flags == '0x002' and int(packet.tcp.window_size) > 1024:
            nmap_scan_detected['tcp_connect'] += 1
            packet_info["detection_details"].append("TCP connect scan detected: SYN flag with window size > 1024")
        elif packet.tcp.flags == '0x002' and int(packet.tcp.window_size) <= 1024:
            nmap_scan_detected['syn'] += 1
            packet_info["detection_details"].append("SYN scan detected: SYN flag with window size <= 1024")
        elif packet.tcp.flags == '0x029':  # XMAS Scan detection
            nmap_scan_detected['xmas'] += 1
            packet_info["detection_details"].append("XMAS scan detected: TCP flags indicating XMAS scan")
        elif packet.tcp.flags == '0x000':  # NULL Scan detection
            nmap_scan_detected['null'] += 1
            packet_info["detection_details"].append("NULL scan detected: No TCP flags set")
        elif packet.tcp.flags == '0x001':  # FIN Scan detection
            nmap_scan_detected['fin'] += 1
            packet_info["detection_details"].append("FIN scan detected: Only FIN flag set")

    def detect_udp_scans(self, packet, nmap_scan_detected, packet_info):
        """
        Detect UDP scans based on packet analysis.
        """
        if packet.udp and hasattr(packet.udp, 'length') and packet.udp.length is not None:
            udp_length = int(packet.udp.length)
            if udp_length <= 8:
                nmap_scan_detected['udp'] += 1
                packet_info["detection_details"].append("UDP scan detected: Packet length <= 8")

    def detect_arp_poisoning(self, packet, arp_poisoning_detected, packet_info):
        """
        Detect ARP poisoning attempts.

        This method checks for ARP packets with an opcode of 2 (ARP response).
        If such a packet is found, it is checked if the IP address has been
        associated with a different MAC address before. If so, it is considered
        an ARP poisoning attempt.
        """
        if packet.arp.opcode == '2':
            entry = (packet.arp.src_proto_ipv4, packet.arp.src_hw_mac)
            if entry in arp_poisoning_detected:
                detail = f"ARP poisoning detected: IP {entry[0]} has multiple MAC addresses."
                logging.info(detail)
                packet_info["detection_details"].append(detail)
            arp_poisoning_detected.add(entry)
        if packet.arp.opcode == '2':
            entry = (packet.arp.src_proto_ipv4, packet.arp.src_hw_mac)
            if entry in arp_poisoning_detected:
                detail = f"ARP poisoning detected: IP {entry[0]} has multiple MAC addresses."
                logging.info(detail)
                packet_info["detection_details"].append(detail)
            arp_poisoning_detected.add(entry)

    def detect_icmp_tunneling(self, packet, packet_info):
        """
        Detect ICMP tunneling based on packet analysis.

        This method checks for ICMP packets with a data length greater than 64.
        If such a packet is found, it is considered a potential ICMP tunneling
        activity.
        """
        if len(packet.icmp.data) > 64:
            detail = "Potential ICMP tunneling detected."
            packet_info["detection_details"].append(detail)
            return 1
        return 0

    def detect_dns_tunneling(self, packet, packet_info):
        """
        Detect DNS tunneling based on packet analysis.
        """
        if packet.dns.qry_name and len(packet.dns.qry_name) > 20:
            detail = "Potential DNS tunneling detected."
            logging.info(detail)
            packet_info["detection_details"].append(detail)
            return 1
        return 0

    def detect_anomalies(self, packet, anomaly_detected, packet_info):
        """
        Detect anomalies in traffic patterns.
        """
        # Example: Detect abnormal traffic volume
        if hasattr(packet, 'ip'):
            anomaly_detected.append(packet.ip.src)
            if anomaly_detected.count(packet.ip.src) > 100:  # Arbitrary threshold
                detail = f"Anomalous traffic volume detected from IP {packet.ip.src}"
                logging.info(detail)
                packet_info["detection_details"].append(detail)


    def generate_json_report(self, packet_reports):
        """
        Generate a JSON report with detailed information for each analyzed packet.
        """
        # Extract the base name of the pcap file (without directory path)
        base_filename = os.path.basename(self.file_path)

        # Extract the filename without extension
        filename_without_ext = os.path.splitext(base_filename)[0]

        # Create a unique output filename using the pcap file name and the current date/time
        output_filename = f"reports/{filename_without_ext}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = os.path.join(os.getcwd(), output_filename)

        # Ensure the 'reports' directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        report = {
            "file_path": self.file_path,
            "analysis_date": datetime.now().isoformat(),
            "packet_reports": packet_reports,
            "attack_stats": self.generate_attack_stats(packet_reports)  # Add attack statistics
        }

        # Write report to JSON file
        with open(output_path, 'w') as json_file:
            json.dump(report, json_file, indent=4)

        print(Fore.CYAN + f"\nJSON report generated: {output_path}")

    def generate_attack_stats(self, packet_reports):
        """
        Generate statistics about the attack based on the packet reports.
        """
        stats = {
            "total_packets": len(packet_reports),
            "tcp_packets": len([p for p in packet_reports if "TCP" in p["protocols"]]),
            "udp_packets": len([p for p in packet_reports if "UDP" in p["protocols"]]),
            "icmp_packets": len([p for p in packet_reports if "ICMP" in p["protocols"]]),
            "arp_packets": len([p for p in packet_reports if "ARP" in p["protocols"]]),
            "dns_packets": len([p for p in packet_reports if "DNS" in p["protocols"]]),
            "unique_source_ips": len(set(p["src_ip"] for p in packet_reports if p["src_ip"])),
            "unique_destination_ips": len(set(p["dst_ip"] for p in packet_reports if p["dst_ip"]))
        }
        return stats

    def print_results(self, nmap_scan_detected, arp_poisoning_detected, icmp_tunnel_detected, dns_tunnel_detected, anomaly_detected):
        """
        Print the results of the analysis in a colored and formatted manner.
        """
        print(Fore.CYAN + "\n=== Analysis Results ===")

        print(Fore.GREEN + "\nNmap Scan Detection:")
        for scan_type, count in nmap_scan_detected.items():
            print(f"  {scan_type} scans detected: {count}")

        print(Fore.GREEN + "\nARP Poisoning Detection:")
        if arp_poisoning_detected:
            for arp_entry in arp_poisoning_detected:
                print(Fore.RED + f"  Suspicious ARP Entry: IP - {arp_entry[0]}, MAC - {arp_entry[1]}")
        else:
            print(Fore.YELLOW + "  No ARP poisoning detected.")

        print(Fore.GREEN + "\nICMP Tunneling Detection:")
        print(f"  Potential ICMP tunneling activities detected: {icmp_tunnel_detected}")

        print(Fore.GREEN + "\nDNS Tunneling Detection:")
        print(f"  Potential DNS tunneling activities detected: {dns_tunnel_detected}")

        print(Fore.GREEN + "\nAnomaly Detection:")
        for anomaly in set(anomaly_detected):
            print(Fore.RED + f"  Anomalous activity detected from IP: {anomaly}")

def main():
    # Argument parser for CLI
    parser = argparse.ArgumentParser(description="Blue Team Traffic Analyzer")
    parser.add_argument('--live', action='store_true', help='Enable live capture mode')
    parser.add_argument('--interface', type=str, help='Network interface for live capture')
    parser.add_argument('--file', type=str, help='Path to a single pcap file or a directory containing pcap files')

    args = parser.parse_args()

    # Initialize the analyzer based on the arguments
    if args.live and args.interface:
        analyzer = BlueTeamTrafficAnalyzer(live_capture=True, interface=args.interface)
        analyzer.run_analysis()
    elif args.file:
        # Check if the path is a directory
        if os.path.isdir(args.file):
            # Loop through each file in the directory
            for filename in os.listdir(args.file):
                file_path = os.path.join(args.file, filename)
                if os.path.isfile(file_path) and filename.endswith('.pcap'):
                    print(Fore.GREEN + f"Analyzing pcap file: {file_path}")
                    analyzer = BlueTeamTrafficAnalyzer(live_capture=False, file_path=file_path)
                    analyzer.run_analysis()  # Run the analysis for each file
        elif os.path.isfile(args.file) and args.file.endswith('.pcap'):
            # If it's a single file, analyze it
            analyzer = BlueTeamTrafficAnalyzer(live_capture=False, file_path=args.file)
            analyzer.run_analysis()  # Run the analysis for the single file
        else:
            print(Fore.RED + "Error: The provided path is not a valid pcap file or directory.")
    else:
        print(Fore.RED + "Error: You must specify either a live capture with --live and --interface or a pcap file with --file.")

if __name__ == '__main__':
    main()
