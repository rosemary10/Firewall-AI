from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv


SUSPICIOUS_PORTS = [21, 22, 23, 445]


def write_log(message):

    with open("../../logs/firewall_logs.txt", "a") as log_file:
        log_file.write(message + "\n")


def save_to_dataset(packet_length, protocol, destination_port, label):

    with open("../../datasets/network_traffic.csv", "a", newline="") as csv_file:

        writer = csv.writer(csv_file)

        writer.writerow([
            packet_length,
            protocol,
            destination_port,
            label
        ])


def process_packet(packet):

    if packet.haslayer(IP):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_length = len(packet)

        print("\n===== PACKET DETECTED =====")

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Packet Length: {packet_length}")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if packet.haslayer(TCP):

            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")

            # Suspicious traffic
            if dst_port in SUSPICIOUS_PORTS or packet_length > 1000:

                label = "suspicious"

                alert_message = (
                    f"{timestamp} | ALERT: Suspicious Traffic | "
                    f"Source IP: {src_ip} | Destination Port: {dst_port}"
                )

                print(alert_message)

                write_log(alert_message)

            else:
                label = "normal"

            # Save packet data into dataset
            save_to_dataset(
                packet_length,
                protocol,
                dst_port,
                label
            )

        elif packet.haslayer(UDP):

            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")

            save_to_dataset(
                packet_length,
                protocol,
                dst_port,
                "normal"
            )


sniff(prn=process_packet, store=False)