import socket
from scapy.all import IP, UDP, sr1, Raw

# IP-адрес и порт туннеля
TUNNEL_SERVER_IP = '192.168.1.121'
TUNNEL_SERVER_PORT = 1234

# IP-адрес и порт конечного UDP-сервера
FINAL_DEST_IP = '1.2.3.1'
FINAL_DEST_PORT = 4321

# Сообщение для отправки
message = "Hello from client"

# Создаем инкапсулированный IP-пакет
# Внешний IP-заголовок: от нашего хоста к туннелю
# Внутренний IP-заголовок: от "виртуального" хоста к конечному серверу
# Внутренний UDP-заголовок: к порту конечного сервера
packet = IP(dst=TUNNEL_SERVER_IP) / UDP(sport=12345, dport=TUNNEL_SERVER_PORT) / IP(dst=FINAL_DEST_IP) / UDP(sport=54321, dport=FINAL_DEST_PORT) / Raw(load=message)

print("Отправка пакета...")
# Отправляем пакет и ждем ответа
response = sr1(packet, timeout=10, verbose=0)

if response:
    # Scapy автоматически разбирает вложенные слои
    if response.haslayer(Raw):
        secret_message = response[Raw].load.decode('utf-8', errors='ignore')
        print(f"Получено секретное сообщение: {secret_message}")
    else:
        print("Ответ получен, но не содержит полезной нагрузки (Raw).")
        response.show()
else:
    print("Ответ от сервера не получен.")