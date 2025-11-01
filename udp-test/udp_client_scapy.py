from scapy.all import sniff, UDP, Raw
import socket
import re

BROADCAST_PORT = 5000

def parse_message(msg):
    match = re.search(r'Connect to me: ([\d\.]+) / (\d+)', msg)
    if match:
        return match.group(1), int(match.group(2))
    return None, None

def handle_broadcast(pkt):
    if UDP in pkt and pkt[UDP].dport == BROADCAST_PORT and Raw in pkt:
        msg = pkt[Raw].load.decode(errors='ignore')
        print(f"Получено сообщение: {msg}")
        server_ip, server_port = parse_message(msg)
        if server_ip and server_port:
            print(f"Подключение к серверу {server_ip}:{server_port}")
            # Отправляем сообщение через обычный сокет
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_sock:
                client_sock.settimeout(1)  # Ограничение ожидания ответа сервера до 1 сек
                client_sock.sendto(b'Hello, server!', (server_ip, server_port))
                try:
                    secret, sender_addr = client_sock.recvfrom(1024)
                    print(f"Секретное сообщение от сервера: {secret.decode()}")
                except socket.timeout:
                    print("Нет секретного сообщения от сервера.")
            # После первого подключения завершаем работу клиента
            return True  # Остановить sniff

print("UDP клиент слушает широковещательные сообщения через Scapy...")
# Слушаем только 1 секунду или до первого успешного подключения
sniff(filter=f"udp and dst port {BROADCAST_PORT}", prn=handle_broadcast, timeout=1, stop_filter=lambda x: handle_broadcast(x))