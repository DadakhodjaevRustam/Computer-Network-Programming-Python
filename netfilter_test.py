# source .venv/bin/activate  
#!/usr/bin/env python3


from netfilterqueue import NetfilterQueue
from scapy.all import *
import os




def print_and_accept(pkt):
    print(pkt)
    pkt.accept()




nfqueue = NetfilterQueue()
nfqueue.bind(5, print_and_accept)




try:
    print("Listen -dport 443 - ")
    nfqueue.run()
except KeyboardInterrupt:
    print('')




finally:
  nfqueue.unbind()
  os.system("iptables -D INPUT -p tcp ! --dport 443 -j NFQUEUE --queue-num 5")