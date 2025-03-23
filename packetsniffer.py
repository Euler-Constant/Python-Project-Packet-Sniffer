from scapy.all import sniff, IP, TCP, UDP, ICMP
import argparse
from collections import deque
from datetime import datetime
import time
from functools import partial

# Configuration for spike detection
SPIKE_THRESHOLD = 100  # Packets per second threshold
WINDOW_SIZE = 5  # Sliding window size in seconds

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Scapy")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff (e.g., eth0)")
    parser.add_argument("-p", "--protocol", type=str, choices=["tcp", "udp", "icmp", "all"],
                        default="all", help="Protocol to filter (tcp, udp, icmp, or all)")
    parser.add_argument("-s", "--src-ip", type=str, help="Filter by source IP address")
    parser.add_argument("-d", "--dst-ip", type=str, help="Filter by destination IP address")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-t", "--threshold", type=int, default=SPIKE_THRESHOLD, 
                        help="Spike threshold in packets per second")
    return parser.parse_args()

def build_filter(args):
    filters = []
    if args.protocol != "all":
        filters.append(args.protocol)
    if args.src_ip:
        filters.append(f"src host {args.src_ip}")
    if args.dst_ip:
        filters.append(f"dst host {args.dst_ip}")
    return " and ".join(filters) if filters else None

def detect_spike(packet_count, elapsed_time, threshold):
    if elapsed_time > 0:
        rate = packet_count / elapsed_time
        if rate > threshold:
            print(f"\033[91m[!] Traffic Spike Detected: {rate:.2f} packets/second exceeds threshold {threshold}\033[0m")
            return True
    return False

def packet_callback(packet, threshold, packet_counts, last_window_time):
    current_time = time.time()
    elapsed_time = current_time - last_window_time[0]

    # Update packet counts in the sliding window
    if elapsed_time >= 1:  # New second elapsed
        packet_counts.append(1)
        total_count = sum(packet_counts)
        if detect_spike(total_count, elapsed_time, threshold):
            last_window_time[0] = current_time  # Reset window after spike
        if len(packet_counts) >= WINDOW_SIZE:
            last_window_time[0] = current_time  # Move window forward
    else:
        if packet_counts:
            packet_counts[-1] += 1
        else:
            packet_counts.append(1)

    # Packet details
    if IP in packet:
        ip_layer = packet[IP]
        protocol_name = "Unknown"
        if TCP in packet:
            protocol_name = "TCP"
        elif UDP in packet:
            protocol_name = "UDP"
        elif ICMP in packet:
            protocol_name = "ICMP"
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"Protocol: {protocol_name} | "
              f"Src IP: {ip_layer.src} | "
              f"Dst IP: {ip_layer.dst} | "
              f"Len: {ip_layer.len}")

def main():
    args = parse_arguments()
    filter_str = build_filter(args)
    
    # Initialize state
    packet_counts = deque(maxlen=WINDOW_SIZE)
    last_window_time = [time.time()]  # Mutable list to allow modification in callback
    
    print(f"Starting sniffer on interface: {args.interface or 'default'}")
    if filter_str:
        print(f"Filter: {filter_str}")
    print(f"Spike threshold: {args.threshold} packets per second")

    try:
        sniff(
            iface=args.interface,
            filter=filter_str,
            prn=partial(packet_callback, threshold=args.threshold, 
                       packet_counts=packet_counts, last_window_time=last_window_time),
            count=args.count,
            store=0
        )
    except PermissionError:
        print("Error: Run this script with administrative privileges.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()