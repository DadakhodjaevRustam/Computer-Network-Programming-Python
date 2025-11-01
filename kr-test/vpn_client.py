import socket
import struct
import fcntl
import select
import sys
import time
from pyroute2 import IPRoute

# Конфигурация - ИЗМЕНИТЕ эти параметры согласно вашему заданию
DEVICE_NAME = "tun0"
LOCAL_VPN_IP = "1.1.1.1"
REMOTE_VPN_IP = "1.1.1.2"
SERVER_HOST = "192.168.1.121"  # IP сервера с туннелем
VPN_PORT = 1234  # Изменено на 1234 согласно вашему заданию

def create_and_configure_tun_interface(device_name: str, local_vpn_ip: str, remote_vpn_ip: str):
    """Создание и настройка TUN интерфейса"""
    try:
        ipr = IPRoute()

        # Создаем TUN интерфейс
        ipr.link("add", ifname=device_name, kind="tuntap", mode="tun")
        
        # Ищем индекс интерфейса
        ifidx = ipr.link_lookup(ifname=device_name)[0]
        
        # Назначаем IP-адрес
        ipr.addr("add", index=ifidx, address=local_vpn_ip, mask=32)
        
        # Устанавливаем MTU
        ipr.link("set", index=ifidx, mtu=1472)
        
        # Включаем интерфейс
        ipr.link('set', index=ifidx, state='up')
        
        # Добавляем маршрут
        ipr.route("add", dst=remote_vpn_ip, mask=32, gateway=local_vpn_ip)
        ipr.close()
        
        print(f"Создан TUN интерфейс {device_name} с IP {local_vpn_ip}")
        return True
    except Exception as e:
        print(f"Ошибка создания TUN интерфейса: {e}")
        return False

def open_tun_interface(device_name: str = "tun0"):
    """Открытие TUN интерфейса для чтения/записи"""
    try:
        tuntap = open("/dev/net/tun", "r+b", buffering=0)
        
        LINUX_IFF_TUN = 0x0001
        LINUX_IFF_NO_PI = 0x1000
        flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
        ifs = struct.pack("16sH22s", device_name.encode(), flags, b"")
        
        LINUX_TUNSETIFF = 0x400454CA
        fcntl.ioctl(tuntap, LINUX_TUNSETIFF, ifs)
        
        print(f"TUN интерфейс {device_name} открыт для чтения/записи")
        return tuntap
    except Exception as e:
        print(f"Ошибка открытия TUN интерфейса: {e}")
        return None

def delete_tun_interface(device_name: str):
    """Удаление TUN интерфейса"""
    try:
        ipr = IPRoute()
        ifidx = ipr.link_lookup(ifname=device_name)[0]
        ipr.link("delete", index=ifidx)
        ipr.close()
        print(f"TUN интерфейс {device_name} удален")
    except Exception as e:
        print(f"Ошибка удаления TUN интерфейса: {e}")

def setup_udp_socket(server_host: str, server_port: int):
    """Настройка UDP сокета для VPN соединения"""
    try:
        # Создаем UDP сокет БЕЗ connect (используем sendto/recvfrom)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)  # Таймаут 5 секунд
        
        # Отправляем инициализационное сообщение
        init_msg = b"init_dummy_vpn"
        sock.sendto(init_msg, (server_host, server_port))
        print(f"Отправлено инициализационное сообщение на {server_host}:{server_port}")
        
        # Ждем ответ от сервера
        data, addr = sock.recvfrom(1024)
        
        if data == b"OK":
            print("VPN соединение установлено")
            sock.settimeout(None)  # Убираем таймаут
            return sock
        else:
            print(f"Неверный ответ от сервера: {data}")
            return None
            
    except socket.timeout:
        print(f"Таймаут при установке VPN соединения с {server_host}:{server_port}")
        print("Убедитесь, что VPN сервер запущен и доступен")
        return None
    except ConnectionRefusedError:
        print(f"Соединение отклонено сервером {server_host}:{server_port}")
        print("Сервер не запущен или не слушает на указанном порту")
        return None
    except Exception as e:
        print(f"Ошибка настройки UDP сокета: {e}")
        return None

def simple_udp_client():
    """Простой UDP клиент для тестирования туннеля"""
    print("Запуск простого UDP клиента для тестирования...")
    
    # Параметры из вашего задания
    tunnel_server = "192.168.1.121"
    tunnel_port = 1234
    target_ip = "1.2.3.1"
    target_port = 4321
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # Отправляем тестовое сообщение
        message = b"Hello tunnel"
        sock.sendto(message, (tunnel_server, tunnel_port))
        print(f"Отправлено сообщение через туннель: {message}")
        
        # Получаем ответ
        data, addr = sock.recvfrom(1024)
        print(f"Получен ответ: {data.decode()}")
        
        sock.close()
        return True
        
    except socket.timeout:
        print("Таймаут! Ответ не получен.")
        return False
    except Exception as e:
        print(f"Ошибка: {e}")
        return False

def main():
    """Основная функция VPN клиента"""
    print("Запуск VPN клиента...")
    
    # Сначала протестируем простой UDP клиент
    print("\n=== Тестирование туннеля ===")
    if not simple_udp_client():
        print("Туннель не работает. Запустите VPN сервер или проверьте настройки.")
        return
    
    print("\n=== Запуск полноценного VPN клиента ===")
    
    tun_fd = None
    vpn_socket = None
    
    try:
        # 1. Создаем и настраиваем TUN интерфейс
        if not create_and_configure_tun_interface(DEVICE_NAME, LOCAL_VPN_IP, REMOTE_VPN_IP):
            return
        
        # 2. Открываем TUN интерфейс
        tun_fd = open_tun_interface(DEVICE_NAME)
        if not tun_fd:
            delete_tun_interface(DEVICE_NAME)
            return
        
        # 3. Настраиваем UDP сокет
        vpn_socket = setup_udp_socket(SERVER_HOST, VPN_PORT)
        if not vpn_socket:
            print("Не удалось установить соединение с VPN сервером")
            if tun_fd:
                tun_fd.close()
            delete_tun_interface(DEVICE_NAME)
            return
        
        print("VPN клиент готов к работе")
        print(f"Локальный VPN IP: {LOCAL_VPN_IP}")
        print(f"Удаленный VPN IP: {REMOTE_VPN_IP}")
        print(f"Сервер: {SERVER_HOST}:{VPN_PORT}")
        
        # 4. Основной цикл обработки пакетов
        while True:
            try:
                rd_sockets, _, _ = select.select([tun_fd, vpn_socket], [], [], 1.0)
                
                for sock in rd_sockets:
                    if sock is tun_fd:
                        data = tun_fd.read(65535)
                        if data:
                            vpn_socket.sendto(data, (SERVER_HOST, VPN_PORT))
                            
                    elif sock is vpn_socket:
                        data, addr = vpn_socket.recvfrom(65535)
                        if data and addr[0] == SERVER_HOST:
                            tun_fd.write(data)
                            
            except KeyboardInterrupt:
                print("\nЗавершение работы по запросу пользователя...")
                break
            except Exception as e:
                print(f"Ошибка в основном цикле: {e}")
                break
                        
    except Exception as e:
        print(f"Критическая ошибка: {e}")
    finally:
        # Корректное завершение
        print("Очистка ресурсов...")
        if tun_fd:
            tun_fd.close()
        if vpn_socket:
            vpn_socket.close()
        delete_tun_interface(DEVICE_NAME)
        print("VPN клиент остановлен")

if __name__ == "__main__":
    main()