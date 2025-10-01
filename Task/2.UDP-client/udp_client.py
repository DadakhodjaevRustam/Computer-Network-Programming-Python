import socket

HOST = 'task.miminet.ru'
PORT = 8010

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    # Отправляем пакет на сервер
    s.sendto(b'Hello, server!', (HOST, PORT))
    # Получаем ответ от сервера
    data, server_addr = s.recvfrom(1024)
    # Декодируем ответ в строку
    response = data.decode('utf-8')
    # Выводим ответ
    print(f"Received response: {response}")


