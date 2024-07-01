from scapy.all import ARP, sr1
import os
import platform

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
        result = os.popen("netstat -r").read().strip()
        print("Resultado netstat -r:", result)  # Depuración
        for line in result.split('\n'):
            if "Default Gateway" in line:
                parts = line.split()
                router_ip = parts[-2]
                return router_ip
    elif sistema_operativo == "Linux":
        result = os.popen("ip route | grep default").read().strip()
        print("Resultado ip route | grep default:", result)  # Depuración
        router_ip = result.split()[2]
        return router_ip
    
    return None

def obtener_mac(ip):
    arp_request = ARP(pdst=ip)
    arp_response = sr1(arp_request, timeout=1, verbose=0)
    if arp_response:
        return arp_response.hwsrc
    else:
        return None

def detectar_modificacion_arp(ip_router, mac_esperada):
    arp_request = ARP(pdst=ip_router)
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

if __name__ == "__main__":
    ip_router = obtener_ip_router()
    if not ip_router:
        print("No se pudo obtener la IP del router.")
        exit(1)  # Salir del script con código de error 1 si no se puede obtener la IP del router

    mac_esperada = input("Introduce la dirección MAC esperada del router: ")

    detectar_modificacion_arp(ip_router, mac_esperada)
