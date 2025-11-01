import socket
import re

BROADCAST_IP = ''         # слушать на всех интерфейсах
BROADCAST_PORT = 5000     # порт для приема broadcast сообщений

def parse_message(msg):
    match = re.search(r'Connect to me: ([\d\.]+) / (\d+)', msg)
    if match:
        return match.group(1), int(match.group(2))
    return None, None

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind((BROADCAST_IP, BROADCAST_PORT))

print("UDP клиент слушает широковещательные сообщения...")

while True:
    data, addr = sock.recvfrom(1024)
    msg = data.decode()
    print(f"Получено сообщение: {msg}")
    server_ip, server_port = parse_message(msg)
    if server_ip and server_port:
        print(f"Подключение к серверу {server_ip}:{server_port}")
        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_sock.settimeout(2)
            send_sock.sendto(b'Hello, server!', (server_ip, server_port))
            # Ждем секретное сообщение от сервера
            try:
                secret, sender_addr = send_sock.recvfrom(1024)
                print(f"Секретное сообщение от сервера: {secret.decode()}")
            except socket.timeout:
                print("Нет секретного сообщения от сервера.")
            send_sock.close()
        except Exception as e:
            print(f"Ошибка отправки: {e}")