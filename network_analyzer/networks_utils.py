# network_utils.py
from scapy.all import IP, TCP, UDP

def analyze_packet(packet, protocol_filter=None):
    """
    Analiza el paquete y lo guarda si cumple el filtro de protocolo.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol_filter and protocol != protocol_filter:
            return  # Filtra protocolos no deseados

        with open("data/analysis_log.txt", "a") as f:
            f.write(f"IP Source: {ip_src} -> IP Destination: {ip_dst}\n")
            if protocol == 6 and TCP in packet:  # TCP
                f.write(f"TCP Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n")
            elif protocol == 17 and UDP in packet:  # UDP
                f.write(f"UDP Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}\n")
            f.write("--------\n")
