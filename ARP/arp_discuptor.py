import sys
from scapy.all import ARP, Ether, srp, get_if_addr

def get_network_range():
    """
    Определяет диапазон сети на основе локального IP-адреса.
    """
    try:
        # Пытаемся получить IP-адрес для интерфейса, переданного в аргументах,
        # или используем 'eth0' по умолчанию.
        local_ip = get_if_addr(sys.argv[1] if len(sys.argv) > 1 else "wlp0s20f3")
        if local_ip == "0.0.0.0":
            raise Exception("Не удалось получить локальный IP-адрес. Пожалуйста, укажите сетевой интерфейс (например, eth0, wlan0).")
            
        ip_parts = local_ip.split('.')
        # Для простоты используем /24 маску (255.255.255.0)
        network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        print(f"[*] Локальный IP-адрес: {local_ip}")
        print(f"[*] Сканируемый диапазон сети: {network}")
        return network
    except Exception as e:
        print(f"[-] Ошибка определения сети: {e}")
        print("[-] Используется значение по умолчанию: 192.168.0.0/24")
        return "192.168.0.0/24"

def scan_network(ip_range):
    """
    Сканирует сеть с помощью ARP-запросов и возвращает список найденных устройств.
    """
    print(f"\n[*] Сканирование сети {ip_range}...")
    # Создаем ARP-запрос для указанного диапазона IP-адресов
    arp_request = ARP(pdst=ip_range)
    
    # Создаем Ethernet-кадр для широковещательной рассылки
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Объединяем кадр и ARP-запрос
    arp_request_broadcast = broadcast / arp_request
    
    # Отправляем пакеты и получаем ответы.
    # srp возвращает кортеж из двух списков: (ответившие, не ответившие)
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for sent_packet, received_packet in answered_list:
        # Извлекаем IP и MAC из полученного пакета
        devices.append({'ip': received_packet.psrc, 'mac': received_packet.hwsrc})
        
    return devices

def print_devices(devices_list):
    """
    Выводит список найденных устройств в отформатированном виде.
    """
    print("\n[+] Обнаружены следующие устройства:")
    print("IP-адрес\t\tMAC-адрес")
    print("-----------------------------------------")
    for device in devices_list:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    ip_range_to_scan = get_network_range()
    found_devices = scan_network(ip_range_to_scan)
    
    if found_devices:
        print_devices(found_devices)
    else:
        print("\n[-] В сети не найдено ни одного активного устройства.")