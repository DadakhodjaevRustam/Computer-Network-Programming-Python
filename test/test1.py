#!/usr/bin/env python3
"""""
Этот скрипт, запущенный вместе с правилом iptables, служит примитивным, 
но работающим средством защиты от DoS-атаки типа "SYN-флуд", блокируя IP-адреса, 
которые пытаются слишком быстро открыть много TCP-сессий.
"""""


from scapy.all import *
from netfilterqueue import NetfilterQueue
from datetime import datetime

info = {}
DELAY=1000
def print_and_accept(pkt):
    dt = IP(pkt.get_payload())
#    print(raw(dt))
    
    dt_tcp = TCP(pkt.get_payload())
    flg = dt_tcp.flags
    dport = dt_tcp.dport
    ip_src = dt.src
    tm = datetime.now()
    is_acept = True
    if "S" in flg:
        if not (ip_src,dport) in info:
            info[(ip_src,dport)] = {'time':tm}
        else:
            df = (tm - info[(ip_src,dport)]['time']).total_seconds()*1000
            info[(ip_src,dport)]['time'] = tm
            if df < DELAY:
                print(tm.ctime(),"ALERT",ip_src,dport)
                is_acept = False
    if is_acept:
        pkt.accept()
nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()

"""
iptables -I INPUT -p tcp ! --dport 22 -j NFQUEUE --queue-num 1
"""