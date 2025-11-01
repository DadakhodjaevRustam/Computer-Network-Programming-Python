import socket
import threading

# Настройки туннеля
LOCAL_LISTEN_IP = '192.168.1.121'      # слушаем нужном ip 
LOCAL_LISTEN_PORT = 1234         # порт, на котором слушает туннель

REMOTE_SERVER_IP = '1.2.3.1'     # адрес конечного UDP-сервера
REMOTE_SERVER_PORT = 4321        # порт конечного UDP-сервера

def forward_client_to_server(sock):
    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Получено {len(data)} байт от клиента {addr}, пересылаем серверу")
        # Пересылаем на реальный сервер
        sock.sendto(data, (REMOTE_SERVER_IP, REMOTE_SERVER_PORT))
        # Запоминаем адрес клиента для обратной пересылки
        global last_client_addr
        last_client_addr = addr
import socket

# Параметры туннеля
LISTEN_IP = '0.0.0.0'           # слушаем на всех интерфейсах
LISTEN_PORT = 4322             # порт, на котором слушает туннель (port+1)
SERVER_IP = '1.2.3.1'           # внутренний сервер
SERVER_PORT = 4321              # порт внутреннего сервера

def main():
    # UDP сокет для туннеля
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"UDP туннель запущен: {LISTEN_IP}:{LISTEN_PORT} -> {SERVER_IP}:{SERVER_PORT}")

    while True:
        # Получаем пакет от клиента
        data, client_addr = sock.recvfrom(65535)
        print(f"Получено {len(data)} байт от клиента {client_addr}, пересылаем серверу")

        # Пересылаем пакет на внутренний сервер
        sock.sendto(data, (SERVER_IP, SERVER_PORT))

        # Ждём ответ от сервера
        server_data, server_addr = sock.recvfrom(65535)
        print(f"Получено {len(server_data)} байт от сервера {server_addr}, пересылаем клиенту")

        # Пересылаем ответ обратно клиенту
        sock.sendto(server_data, client_addr)

if __name__ == "__main__":
    main()
def forward_server_to_client(sock):
    while True:
        data, addr = sock.recvfrom(65535)
        print(f"Получено {len(data)} байт от сервера {addr}, пересылаем клиенту")
        # Пересылаем обратно клиенту
        if last_client_addr:
            sock.sendto(data, last_client_addr)

if __name__ == "__main__":
    # UDP сокет для туннеля
    tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tunnel_sock.bind((LOCAL_LISTEN_IP, LOCAL_LISTEN_PORT))
    last_client_addr = None

    # Поток для пересылки от клиента к серверу
    t1 = threading.Thread(target=forward_client_to_server, args=(tunnel_sock,))
    t1.daemon = True
    t1.start()

    # Поток для пересылки от сервера к клиенту
    t2 = threading.Thread(target=forward_server_to_client, args=(tunnel_sock,))
    t2.daemon = True
    t2.start()

    print(f"UDP туннель запущен: {LOCAL_LISTEN_IP}:{LOCAL_LISTEN_PORT} <-> {REMOTE_SERVER_IP}:{REMOTE_SERVER_PORT}")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Туннель остановлен.")