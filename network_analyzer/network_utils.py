#network_utils.py
from scapy.all import IP, TCP, UDP, Ether, Raw
from datetime import datetime
import os
import socket

# Asegura que el directorio de logs exista
if not os.path.exists("data"):
    os.makedirs("data")

def analyze_packet(packet, protocol_filter=None):
    # Obtiene la marca de tiempo de cada paquete
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = f"Timestamp: {timestamp}\n"
    
    # Obtiene el tamaño del paquete en bytes
    packet_size = len(packet)
    report += f"Packet Size: {packet_size} bytes\n"

    # Añade la información de la capa de enlace de datos (Ethernet)
    if Ether in packet:
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        report += f"MAC Source: {mac_src} -> MAC Destination: {mac_dst}\n"
    
     

    # Analiza la capa IP
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ttl = packet[IP].ttl
        protocol = packet[IP].proto

        # Resolución inversa de DNS para la IP de destino
        try:
            dst_host = socket.gethostbyaddr(ip_dst)[0]
        except socket.herror:
            dst_host = "Desconocido"  # Si no se puede resolver la IP

        try:
            src_host = socket.gethostbyname(ip_src)
        except socket.error:
            src_host = ip_src  # Si no se puede resolver, usamos la IP directamente

        report += f"IP Source: {ip_src} (host: {src_host}) -> IP Destination: {ip_dst} (Host: {dst_host})\n"
        report += f"TTL: {ttl}\n"
        
        # Opciones de encabezado IP (si existen)
        if packet[IP].options:
            report += f"IP Options: {packet[IP].options}\n"
        
        # Filtra el protocolo si se ha especificado
        if protocol_filter and protocol != protocol_filter:
            return  # Filtra protocolos no deseados

        # Analiza TCP
        if protocol == 6 and TCP in packet:  # TCP
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            flags = packet[TCP].flags
            window_size = packet[TCP].window
            report += f"TCP Source Port: {port_src} -> TCP Destination Port: {port_dst}\n"
            report += f"Sequence Number: {seq_num}, Acknowledgment Number: {ack_num}\n"
            report += f"Flags: {flags}\n"
            report += f"Window Size: {window_size}\n"

            # Datos en capa de aplicación (HTTP, si es detectado)
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if b"HTTP" in payload:
                    report += f"HTTP Payload: {payload[:100]}...\n"  # Muestra solo los primeros 100 bytes

        # Analiza UDP
        elif protocol == 17 and UDP in packet:  # UDP
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            report += f"UDP Source Port: {port_src} -> UDP Destination Port: {port_dst}\n"
            
            # Análisis DNS en capa de aplicación (si es detectado)
            if packet.haslayer(Raw) and b"DNS" in packet[Raw].load:
                report += f"DNS Payload: {packet[Raw].load[:100]}...\n"  # Muestra los primeros 100 bytes

    # Delimitador de paquetes
    report += "--------\n"

    # Escribe el reporte en el archivo de log
    with open("data/analysis_log.txt", "a") as f:
        f.write(report)
    
    return report