import socket


HOST = 'localhost'
PORT = 40000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
print(f"Сервер запущен на {HOST}:{PORT}")
while True:
    conn, addr = s.accept()
    with conn:
        print(f"Подключение от {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Получено: {data.decode()}")
            conn.sendall(data)
            
