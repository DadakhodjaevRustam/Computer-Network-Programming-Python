import socket
import time
import random
import threading

BROADCAST_IP = '192.168.3.255'
BROADCAST_PORT = 5000
SERVER_IP = '0.0.0.0'
ANNOUNCE_IP = '192.168.3.46'
SECRET_MESSAGE = "Secret: Hello from server!"

current_port = random.randint(10000, 60000)
lock = threading.Lock()

def broadcaster():
    global current_port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        with lock:
            current_port = random.randint(10000, 60000)
            message = f"Connect to me: {ANNOUNCE_IP} / {current_port}"
        sock.sendto(message.encode(), (BROADCAST_IP, BROADCAST_PORT))
        print(f"[Broadcast] {message}")
        time.sleep(2)

def receiver():
    global current_port
    while True:
        with lock:
            port = current_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((SERVER_IP, port))
        print(f"[Receiver] Listening on {SERVER_IP}:{port}")
        sock.settimeout(2)
        try:
            data, addr = sock.recvfrom(1024)
            print(f"[Receiver] Received from {addr}: {data.decode()}")
            # Отправляем секретное сообщение обратно отправителю
            sock.sendto(SECRET_MESSAGE.encode(), addr)
            print(f"[Receiver] Sent secret message to {addr}")
        except socket.timeout:
            pass
        sock.close()
        time.sleep(2)

if __name__ == "__main__":
    t1 = threading.Thread(target=broadcaster, daemon=True)
    t2 = threading.Thread(target=receiver, daemon=True)
    t1.start()
    t2.start()
    while True:
        time.sleep(1)