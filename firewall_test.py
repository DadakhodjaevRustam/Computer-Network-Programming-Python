#!/usr/bin/env python3

from scapy.all import *
from netfilterqueue import NetfilterQueue
from datetime import datetime

info = {}
DELAY = 1000  # 1000 ms = 1 second

def print_and_accept(pkt):
    try:
        # Получаем сырые данные пакета
        raw_data = pkt.get_payload()
        
        # Парсим как IP-пакет
        ip_pkt = IP(raw_data)
        
        # Проверяем наличие TCP слоя
        if ip_pkt.haslayer(TCP):
            tcp_layer = ip_pkt[TCP]
            flg = tcp_layer.flags
            dport = tcp_layer.dport
            ip_src = ip_pkt.src
            tm = datetime.now()
            is_accept = True
            
            if "S" in str(flg):  # SYN flag
                key = (ip_src, dport)
                if key not in info:
                    info[key] = {'time': tm}
                else:
                    time_diff = (tm - info[key]['time']).total_seconds() * 1000
                    info[key]['time'] = tm
                    if time_diff < DELAY:
                        print(f"{tm.ctime()} ALERT {ip_src} {dport} (interval: {time_diff:.2f}ms)")
                        is_accept = False
            
            if is_accept:
                pkt.accept()
            else:
                pkt.drop()  # Блокируем подозрительный пакет
        else:
            pkt.accept()  # Принимаем не-TCP пакеты
            
    except Exception as e:
        # В случае ошибки парсинга принимаем пакет
        pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(5, print_and_accept)

print("[+] Firewall started. Press Ctrl+C to stop.")

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('\n[+] Stopping firewall...')
finally:
    nfqueue.unbind()
    # Очищаем правило iptables при завершении
    print("[+] Cleaning iptables rules...")
    import os
    os.system("iptables -D INPUT -p tcp ! --dport 22 -j NFQUEUE --queue-num 5")