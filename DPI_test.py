import os

from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
from scapy.packet import Raw
from scapy.sendrecv import send

MSG_TYPE = 0
HANDSHAKE_TYPE = 5

HANDSHAKE = 0x16
CLIENT_HELLO = 0x01

SPLIT_AT = 2

tcp_streams = {}

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(TCP) and scapy_packet[TCP].payload:
        tcp_payload = bytes(scapy_packet[TCP].payload)
        stream_id = (scapy_packet[IP].src, scapy_packet[TCP].sport,
                     scapy_packet[IP].dst, scapy_packet[TCP].dport)
        if tcp_payload[MSG_TYPE] == HANDSHAKE and tcp_payload[HANDSHAKE_TYPE] == CLIENT_HELLO:
            tcp_streams[stream_id] = [tcp_payload, scapy_packet[IP].seq, scapy_packet[IP].ack]
            packet.drop()
        elif stream_id in tcp_streams:
            tcp_streams[stream_id][0] += tcp_payload
            if TLS(tcp_streams[stream_id][0]).haslayer(TLSClientHello):
                scapy_packet_p1 = scapy_packet[IP] / scapy_packet[TCP]
                scapy_packet_p2 = scapy_packet[IP] / scapy_packet[TCP]

                del scapy_packet_p1[IP].len, scapy_packet_p1[IP].chksum, scapy_packet_p1[TCP].chksum, scapy_packet_p1[TCP].payload, scapy_packet_p1[TCP].seq, scapy_packet_p1[TCP].ack
                del scapy_packet_p2[IP].len, scapy_packet_p2[IP].chksum, scapy_packet_p2[TCP].chksum, scapy_packet_p2[TCP].payload, scapy_packet_p2[TCP].seq, scapy_packet_p2[TCP].ack

                scapy_packet_p1 /= Raw(tcp_streams[stream_id][0][:SPLIT_AT])
                scapy_packet_p2 /= Raw(tcp_streams[stream_id][0][SPLIT_AT:])

                scapy_packet_p1[TCP].seq = tcp_streams[stream_id][1]
                scapy_packet_p2[TCP].seq = tcp_streams[stream_id][1] + SPLIT_AT

                scapy_packet_p1[TCP].ack = tcp_streams[stream_id][2]
                scapy_packet_p2[TCP].ack = tcp_streams[stream_id][2]

                send(scapy_packet_p2, verbose=False)
                send(scapy_packet_p1, verbose=False)

                del tcp_streams[stream_id]

                packet.drop()
        else:
            packet.accept()
    else:
        packet.accept()


os.system("iptables -I INPUT -p tcp ! --dport 443 -j NFQUEUE --queue-num 5")

nfqueue = NetfilterQueue()
nfqueue.bind(5, process_packet)
try:
    nfqueue.run()
finally:
    os.system("iptables -D INPUT -p tcp ! --dport 443 -j NFQUEUE --queue-num 5")
    nfqueue.unbind()