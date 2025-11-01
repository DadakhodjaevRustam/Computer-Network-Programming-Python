import os
import select
import socket
import struct
import fcntl
import threading
import time

# --- Константы ---
TUNNEL_SERVER_IP = '192.168.1.121'
TUNNEL_SERVER_PORT = 1234
FINAL_DEST_IP = '1.2.3.1'
FINAL_DEST_PORT = 4321
TUN_IP = '1.2.3.2'
TUN_NETMASK = '255.255.255.0'

# --- Константы для работы с TUN/TAP и сетевыми интерфейсами ---
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFF_UP = 0x1
IFF_RUNNING = 0x40

SIOCSIFADDR = 0x8916  # Установить IP-адрес интерфейса
SIOCSIFNETMASK = 0x891c # Установить маску подсети
SIOCSIFFLAGS = 0x8914  # Установить флаги интерфейса
SIOCGIFFLAGS = 0x8913  # Получить флаги интерфейса
SIOCADDRT = 0x890B    # Добавить маршрут
SIOCDELRT = 0x890C    # Удалить маршрут

# --- Функции для конфигурации сети через ioctl ---

def configure_interface(ifname, ip, netmask):
    """Настраивает IP-адрес и маску подсети для указанного интерфейса."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Установка IP-адреса
        addr = struct.pack('16sH2s4s8s', ifname.encode('utf-8'), socket.AF_INET, b'\x00'*2, socket.inet_aton(ip), b'\x00'*8)
        fcntl.ioctl(sock, SIOCSIFADDR, addr)

        # Установка маски подсети
        mask = struct.pack('16sH2s4s8s', ifname.encode('utf-8'), socket.AF_INET, b'\x00'*2, socket.inet_aton(netmask), b'\x00'*8)
        fcntl.ioctl(sock, SIOCSIFNETMASK, mask)
    finally:
        sock.close()

def set_interface_up(ifname):
    """Активирует (поднимает) указанный сетевой интерфейс."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Получаем текущие флаги
        flags_req = struct.pack('16sH', ifname.encode('utf-8'), 0)
        flags = struct.unpack('16sH', fcntl.ioctl(sock, SIOCGIFFLAGS, flags_req))[1]

        # Устанавливаем флаги UP и RUNNING
        flags |= (IFF_UP | IFF_RUNNING)
        new_flags_req = struct.pack('16sH', ifname.encode('utf-8'), flags)
        fcntl.ioctl(sock, SIOCSIFFLAGS, new_flags_req)
    finally:
        sock.close()

def add_route(ifname, dest_ip):
    """Добавляет маршрут в таблицу маршрутизации ядра."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        dest_as_int = struct.unpack('!I', socket.inet_aton(dest_ip))[0]
        mask_as_int = struct.unpack('!I', socket.inet_aton('255.255.255.255'))[0]
        gateway_as_int = 0
        flags = 0x0001 | 0x0004  # RTF_UP | RTF_HOST

        # Структура rtentry для ioctl SIOCADDRT
        # Формат: dst, gateway, genmask, flags, metric, ref, use, dev
        # Используем 'I' для 4-байтных IP-адресов
        rt_entry = struct.pack(
            'IIIHiii16s',
            dest_as_int,
            gateway_as_int,
            mask_as_int,
            flags,
            0, 0, 0,  # metric, ref, use
            ifname.encode('utf-8')
        )
        fcntl.ioctl(sock, SIOCADDRT, rt_entry)
    finally:
        sock.close()

def delete_route(ifname, dest_ip):
    """Удаляет маршрут из таблицы маршрутизации ядра."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        dest_as_int = struct.unpack('!I', socket.inet_aton(dest_ip))[0]
        mask_as_int = struct.unpack('!I', socket.inet_aton('255.255.255.255'))[0]
        gateway_as_int = 0
        flags = 0x0001 | 0x0004  # RTF_UP | RTF_HOST

        rt_entry = struct.pack(
            'IIIHiii16s',
            dest_as_int,
            gateway_as_int,
            mask_as_int,
            flags,
            0, 0, 0,
            ifname.encode('utf-8')
        )
        fcntl.ioctl(sock, SIOCDELRT, rt_entry)
    except IOError as e:
        print(f"Не удалось удалить маршрут (это может быть нормально при завершении): {e}")
    finally:
        sock.close()

# --- Основная логика ---

# 1. Создание TUN-интерфейса
try:
    tun = open('/dev/net/tun', 'r+b', buffering=0)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    ifr = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifr[:16].strip(b'\x00').decode('utf-8')
    print(f"Интерфейс {ifname} создан.")
except Exception as e:
    print(f"Ошибка создания TUN-интерфейса: {e}")
    print("Пожалуйста, запустите скрипт с правами sudo и убедитесь, что модуль 'tun' загружен.")
    exit(1)

try:
    # 2. Настройка и активация интерфейса
    configure_interface(ifname, TUN_IP, TUN_NETMASK)
    set_interface_up(ifname)
    print(f"Интерфейс {ifname} настроен: IP={TUN_IP}, поднят.")

    # 3. Добавление маршрута
    add_route(ifname, FINAL_DEST_IP)
    print(f"Маршрут для {FINAL_DEST_IP} через {ifname} добавлен.")

    # 4. Создание UDP-сокета для связи с туннельным сервером
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 5. Запуск клиентского потока для отправки/получения данных
    running = True
    def client_task():
        global running
        time.sleep(1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
            try:
                print("\n[Клиент] Отправка сообщения серверу...")
                client_socket.sendto(b"get secret", (FINAL_DEST_IP, FINAL_DEST_PORT))
                print("[Клиент] Ожидание ответа...")
                data, addr = client_socket.recvfrom(1024)
                print(f"[Клиент] Получено секретное сообщение: {data.decode()}")
            except Exception as e:
                print(f"[Клиент] Ошибка: {e}")
            finally:
                running = False

    client_thread = threading.Thread(target=client_task)
    client_thread.start()

    # 6. Основной цикл пересылки пакетов
    print("Запуск пересылки через туннель...")
    while running:
        r, w, x = select.select([tun, udp_sock], [], [], 1)
        if not r:
            continue
        if tun in r:
            packet = os.read(tun.fileno(), 4096)
            print(f"-> Пересылка пакета с {ifname} на туннельный сервер")
            udp_sock.sendto(packet, (TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT))
        if udp_sock in r:
            packet, addr = udp_sock.recvfrom(4096)
            print(f"<- Пересылка пакета от туннельного сервера на {ifname}")
            os.write(tun.fileno(), packet)

finally:
    # 7. Очистка ресурсов
    print("\nОчистка...")
    if 'client_thread' in locals() and client_thread.is_alive():
        client_thread.join(timeout=1)
    
    # Удаление маршрута и отключение интерфейса
    if 'ifname' in locals():
        delete_route(ifname, FINAL_DEST_IP)
        os.system(f'ip link set {ifname} down') # os.system проще для отключения
        print(f"Интерфейс {ifname} отключен, маршрут удален.")

    if 'tun' in locals():
        tun.close()
    if 'udp_sock' in locals():
        udp_sock.close()
    
    print("Очистка завершена.")
