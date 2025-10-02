import scapy.all as scapy
from scapy.all import ARP, Ether, sniff
import datetime
import json
import os
from collections import defaultdict

class ARPDeviceMonitor:
    def __init__(self):
        self.known_devices = {}  # IP -> MAC mapping
        self.device_history = defaultdict(list)  # IP -> list of events
        self.device_info = {}  # IP -> additional info
        self.load_known_devices()
        
    def load_known_devices(self):
        """Загружаем известные устройства из файла"""
        try:
            if os.path.exists('known_devices.json'):
                with open('known_devices.json', 'r') as f:
                    self.known_devices = json.load(f)
                    print(f"[*] Загружено {len(self.known_devices)} известных устройств")
        except Exception as e:
            print(f"[-] Ошибка загрузки известных устройств: {e}")
    
    def save_known_devices(self):
        """Сохраняем известные устройства в файл"""
        try:
            with open('known_devices.json', 'w') as f:
                json.dump(self.known_devices, f, indent=2)
        except Exception as e:
            print(f"[-] Ошибка сохранения устройств: {e}")
    
    def get_vendor_info(self, mac_address):
        """Определяем производителя по MAC-адресу (упрощенно)"""
        # Базовая идентификация по OUI (первые 3 байта)
        oui = mac_address[:8].upper()
        vendors = {
            "00:00:00": "XEROX",
            "00:01:00": "HEWLETT-PACKARD",
            "00:04:00": "NOVELL",
            "00:05:00": "IBM",
            "00:0C:29": "VMware",
            "00:0C:F1": "Cisco",
            "00:10:18": "BROADCOM",
            "00:11:32": "SAMSUNG",
            "00:12:00": "SONY",
            "00:13:10": "CISCO-LINKSYS",
            "00:15:5D": "MICROSOFT",
            "00:16:3E": "XENSOURCE",
            "00:19:B9": "INTEL",
            "00:1A:1E": "MURATA",
            "00:1B:63": "APPLE",
            "00:1C:B3": "INTEL",
            "00:1D:60": "LG ELECTRONICS",
            "00:1E:06": "SAMSUNG ELECTRO",
            "00:1F:3A": "MICROSOFT",
            "00:21:5A": "HTC",
            "00:22:41": "NINTENDO",
            "00:23:12": "SAMSUNG ELECTRO",
            "00:24:E8": "MURATA",
            "00:26:37": "MICROSOFT",
            "00:50:BA": "DIGI INTERNATIONAL",
            "00:80:77": "APPLE",
            "00:90:A9": "ASUSTEK",
            "00:C0:B7": "MICROSOFT",
            "00:D0:41": "PRISM",
            "00:E0:4C": "REALTEK SEMICONDUCTOR",
            "00:E0:66": "SYMBIOS",
            "00:FC:70": "HON HAI PRECISION",
            "00:FF:FF": "BROADCAST"
        }
        
        for vendor_oui, vendor_name in vendors.items():
            if oui.startswith(vendor_oui):
                return vendor_name
        return "Unknown"
    
    def analyze_arp_packet(self, packet):
        """Анализируем ARP-пакет и определяем новые устройства"""
        if packet.haslayer(ARP):
            arp_layer = packet.getlayer(ARP)
            timestamp = datetime.datetime.now()
            
            # Получаем информацию из пакета
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc
            dst_ip = arp_layer.pdst
            operation = "ARP Request" if arp_layer.op == 1 else "ARP Reply"
            
            # Проверяем, новое ли это устройство
            is_new_device = False
            is_mac_changed = False
            
            if src_ip not in self.known_devices:
                is_new_device = True
                print(f"\n🆕 НОВОЕ УСТРОЙСТВО ОБНАРУЖЕНО!")
                print(f"   IP: {src_ip}")
                print(f"   MAC: {src_mac}")
                print(f"   Производитель: {self.get_vendor_info(src_mac)}")
                print(f"   Время: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   Тип: {operation}")
                
                # Сохраняем новое устройство
                self.known_devices[src_ip] = src_mac
                self.save_known_devices()
                
            elif self.known_devices[src_ip] != src_mac:
                is_mac_changed = True
                old_mac = self.known_devices[src_ip]
                print(f"\n⚠️  ИЗМЕНЕНИЕ MAC-АДРЕСА!")
                print(f"   IP: {src_ip}")
                print(f"   Старый MAC: {old_mac}")
                print(f"   Новый MAC: {src_mac}")
                print(f"   Производитель: {self.get_vendor_info(src_mac)}")
                print(f"   Время: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Обновляем MAC-адрес
                self.known_devices[src_ip] = src_mac
                self.save_known_devices()
            
            # Логируем активность
            event = {
                'timestamp': timestamp.isoformat(),
                'mac': src_mac,
                'operation': operation,
                'target_ip': dst_ip
            }
            self.device_history[src_ip].append(event)
            
            # Показываем активность известных устройств (если не новое)
            if not is_new_device and not is_mac_changed:
                print(f"📱 {src_ip} ({src_mac}) -> {operation} -> {dst_ip}")
    
    def show_statistics(self):
        """Показываем статистику по устройствам"""
        print(f"\n📊 СТАТИСТИКА УСТРОЙСТВ:")
        print(f"Всего устройств: {len(self.known_devices)}")
        
        for ip, mac in self.known_devices.items():
            history = self.device_history[ip]
            if history:
                last_seen = history[-1]['timestamp']
                vendor = self.get_vendor_info(mac)
                print(f"  {ip} ({mac}) - {vendor}")
                print(f"    Последняя активность: {last_seen}")
                print(f"    Всего событий: {len(history)}")
    
    def export_results(self):
        """Экспортируем результаты в JSON"""
        results = {
            'known_devices': self.known_devices,
            'device_history': dict(self.device_history),
            'scan_time': datetime.datetime.now().isoformat()
        }
        
        with open('arp_scan_results.json', 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Результаты сохранены в arp_scan_results.json")

def main():
    """Главная функция"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║              ARP МОНИТОР НОВЫХ УСТРОЙСТВ                     ║
    ║                                                              ║
    ║  Сканирует сеть и обнаруживает новые устройства через ARP  ║
    ║  Отслеживает изменения MAC-адресов и логирует активность     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Создаем монитор
    monitor = ARPDeviceMonitor()
    
    try:
        print("[*] Запуск ARP-мониторинга...")
        print("[*] Ожидание ARP-пакетов... (Ctrl+C для остановки)")
        
        # Запускаем перехват ARP-пакетов
        sniff(filter="arp", prn=monitor.analyze_arp_packet, store=0)
        
    except KeyboardInterrupt:
        print("\n\n[*] Остановка мониторинга")
        monitor.show_statistics()
        monitor.export_results()
        print("[+] Работа завершена")
        
    except Exception as e:
        print(f"[-] Ошибка: {e}")

if __name__ == "__main__":
    # Проверяем права root
    try:
        # Проверка через scapy
        scapy.conf.L3socket
    except:
        print("[-] Этот скрипт требует прав root!")
        print("[-] Запустите с помощью: sudo python arp_device_monitor.py")
        exit(1)
    
    main()