# analyzer.py
from scapy.all import sniff
from network_utils import analyze_packet

def packet_callback(packet):
    analyze_packet(packet, protocol_filter=6)  # 6 es TCP, 17 es UDP

def main():
    print("Iniciando la captura de paquetes...")
    sniff(prn=packet_callback, count=10)

if __name__ == "__main__":
    main()