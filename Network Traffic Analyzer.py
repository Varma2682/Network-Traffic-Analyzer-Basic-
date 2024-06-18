from scapy.all import sniff

def analyze_traffic(packets):
  """
  Analyzes captured network packets and prints basic information.

  Args:
      packets (list): A list of captured packets.
  """
  for packet in packets:
    if packet.haslayer(IP):
      src_ip = packet[IP].src
      dst_ip = packet[IP].dst
      protocol = packet[IP].proto

      # Extract port information if available (transport layer protocols)
      if protocol in [TCP, UDP]:
        src_port = packet[packet.proto].sport
        dst_port = packet[packet.proto].dport
        print(f"Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} - Protocol: {protocol}")
      else:
        print(f"Source: {src_ip} -> Destination: {dst_ip} - Protocol: {protocol}")

# Capture packets on a specific interface (replace with your desired interface)
interface = "eth0"  # Replace with your network interface name (e.g., 'eth0', 'wlan0')
print(f"Capturing traffic on interface: {interface}")

# Capture packets and call the analyze_traffic function
sniff(iface=interface, prn=analyze_traffic)

print("** Packet capture stopped. Analyze the printed information for insights.")
