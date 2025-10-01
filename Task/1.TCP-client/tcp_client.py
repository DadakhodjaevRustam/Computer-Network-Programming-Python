import socket
from PIL import Image

HOST = 'task.miminet.ru'
PORT = 8010

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Получаем данные от сервера
    data = b''
    while True:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
        # Проверяем, что мы получили весь файл
        if chunk.endswith(b'\x0d\x0a\x0d\x0a'):
            break
    
    # Переворачиваем данные
    reversed_data = data[::-1]

    # Сохраняем правильный PNG файл
    with open('reversed.png', 'wb') as f:
        f.write(reversed_data)

    # Открываем и смотрим 
    image = Image.open('reversed.png')
    image.show()
  
    
