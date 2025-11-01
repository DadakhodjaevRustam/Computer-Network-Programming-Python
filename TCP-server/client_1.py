import socket

HOST = 'localhost'
PORT = 40000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    msg = "scapy packet 123"
    s.sendall(msg.encode())
    data = s.recv(1024)
    print(f"Ответ от сервера: {data.decode()}")