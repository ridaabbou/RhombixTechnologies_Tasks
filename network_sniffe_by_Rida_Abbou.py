import scapy.all as scapy

# Set up the packet capture filter (optional)
# You can modify or remove the filter to capture all traffic
# filter = "ip"  # Uncomment this to capture all IP packets

# Create a sniffing callback function
def packet_callback(packet):
    # Print Ethernet frame details
    if packet.haslayer(scapy.Ether):
        dest_mac = packet[scapy.Ether].dst
        src_mac = packet[scapy.Ether].src
        print(f"Ethernet Frame:\nDestination MAC: {dest_mac}, Source MAC: {src_mac}")
        
    # Analyze the IP layer
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

        # Check for transport layer protocols
        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
        elif packet.haslayer(scapy.ICMP):
            print("ICMP Packet")

        print("-" * 50)

# Start the sniffer
scapy.sniff(prn=packet_callback, count=0)  # count=0 means infinite capture
