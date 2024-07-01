from scapy.all import ARP, sr1
import os
import platform
import re

class ARPEntry:
    def __init__(self, ip, mac, interface):
        self.ip = ip
        self.mac = mac
        self.interface = interface

    def __str__(self):
        return f"IP: {self.ip}, MAC: {self.mac}, Interface: {self.interface}"

def obtener_ip_router():
    sistema_operativo = platform.system()
    
    if sistema_operativo == "Windows":
        try:
            result = os.popen("ipconfig /all").read().strip()
            print("Resultado ipconfig /all:", result)  # Depuración
            lines = result.split('\n')
            for line in lines:
                if "Puerta de enlace predeterminada" in line:
                    parts = line.split(':')
                    ip_router = parts[-1].strip()
                    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_router):
                        return ip_router
                    else:
                        continue
        except Exception as e:
            print(f"Error al obtener la IP del router en Windows: {e}")
            return None
    
    elif sistema_operativo == "Linux":
        try:
            result = os.popen("ip route | grep default").read().strip()
            print("Resultado ip route | grep default:", result)  # Depuración
            router_ip = result.split()[2]
            return router_ip
        except Exception as e:
            print(f"Error al obtener la IP del router en Linux: {e}")
            return None
    
    return None

def obtener_mac(ip):
    arp_request = ARP(pdst=ip)
    try:
        arp_response = sr1(arp_request, timeout=1, verbose=0)
        if arp_response:
            return arp_response.hwsrc
        else:
            return None
    except Exception as e:
        print(f"Error al enviar solicitud ARP a {ip}: {e}")
        return None

def detectar_modificacion_arp(ip_router, mac_esperada):
    arp_request = ARP(pdst=ip_router)
    try:
        arp_response = sr1(arp_request, timeout=1, verbose=0)
        if arp_response:
            mac_encontrada = arp_response.hwsrc
            if mac_encontrada != mac_esperada:
                print("[!] ¡La tabla ARP ha sido modificada!")
                print(f"[!] MAC esperada: {mac_esperada}, MAC encontrada: {mac_encontrada}")
            else:
                print("[+] La tabla ARP es correcta. No se detectó spoofing.")
        else:
            print("No se recibió respuesta para la solicitud ARP.")
    except Exception as e:
        print(f"Error al enviar solicitud ARP a {ip_router}: {e}")

if __name__ == "__main__":
    ip_router = obtener_ip_router()
    if not ip_router:
        print("No se pudo obtener la IP del router.")
        exit(1)  # Salir del script con código de error 1 si no se puede obtener la IP del router

    mac_esperada = obtener_mac(ip_router)
    if not mac_esperada:
        print(f"No se pudo obtener la dirección MAC esperada para {ip_router}.")
        exit(1)  # Salir del script con código de error 1 si no se puede obtener la MAC esperada

    detectar_modificacion_arp(ip_router, mac_esperada)
