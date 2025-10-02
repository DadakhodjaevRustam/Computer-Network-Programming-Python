from scapy.all import sniff, IP, UDP, Raw

def xor_cipher(data, key):
    """Простое XOR-шифрование/дешифрование."""
    return bytes([b ^ key for b in data])

# ВАЖНО: Ключ должен быть таким же, как на сервере!
encryption_key = 42

def packet_handler(packet):
    """
    Эта функция вызывается для каждого захваченного пакета,
    который соответствует нашему фильтру.
    """
    # Проверяем, что в пакете есть полезная нагрузка (слой Raw)
    if packet.haslayer(Raw):
        sender_ip = packet[IP].src
        encrypted_payload = packet[Raw].load
        
        # ШАГ 1: Дешифруем полученные данные
        decrypted_payload = xor_cipher(encrypted_payload, encryption_key)
        
        try:
            # ШАГ 2: Теперь декодируем расшифрованные байты в строку
            message = decrypted_payload.decode('utf-8')
            print(f"Received and decrypted message: '{message}' from {sender_ip}")
        except UnicodeDecodeError:
            # Эта ошибка может возникнуть, если ключ неверный или пакет поврежден
            print(f"Could not decode payload from {sender_ip} after decryption. Raw: {decrypted_payload}")

print("Starting UDP listener with scapy on port 7000...")
print("Press Ctrl+C to stop.")

try:
    # Слушаем только UDP-пакеты на порту 7000
    sniff(filter="udp and port 7000", prn=packet_handler, store=0)

except PermissionError:
    print("\nPermissionError: You might need to run this script with root privileges.")
    print("Try running with 'sudo python udp_client.py'")
except KeyboardInterrupt:
    print("\nSniffer stopped.")
except Exception as e:
    print(f"An error occurred: {e}")