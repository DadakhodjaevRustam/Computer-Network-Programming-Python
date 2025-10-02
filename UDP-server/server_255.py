from scapy.all import IP, UDP, send
import time

def xor_cipher(data, key):
    """Простое XOR-шифрование/дешифрование."""
    return bytes([b ^ key for b in data])

# Ключ для шифрования (число от 0 до 255)
# Важно: клиент должен использовать тот же ключ для дешифрования!
encryption_key = 42

# Широковещательный адрес для вашей подсети
broadcast_ip = "255.255.255.255"
port = 7000
message_text = b"This is a secret message!"

print(f"Starting encrypted broadcast to {broadcast_ip}:{port} every 2 seconds.")
print("Press Ctrl+C to stop.")

try:
    while True:
        # Шифруем сообщение перед отправкой
        message_bytes = message_text
        encrypted_message = xor_cipher(message_bytes, encryption_key)

        # Создаем и отправляем пакет
        packet = IP(dst=broadcast_ip) / UDP(dport=port) / encrypted_message
        send(packet, verbose=0)
        
        print(f"Sent encrypted packet. Original: '{message_text}'")
        
        # Ждем 2 секунды
        time.sleep(2)

except PermissionError:
    print("\nPermissionError: You might need to run this script with root privileges.")
    print("Try running with 'sudo python server_255.py'")
except KeyboardInterrupt:
    print("\nServer is shutting down.")
except Exception as e:
    print(f"\nAn error occurred: {e}")