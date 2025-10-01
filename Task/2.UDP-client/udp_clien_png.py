import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

HOST = "task.miminet.ru"
PORT = 8011

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(10)  # Set a timeout for socket operations

received_data = b''
flag = 0

try:
    while True:
        client.sendto(b"hello!", (HOST, PORT))
        chunk, _ = client.recvfrom(1500)
        size = len(chunk)
        logger.info(f"Received chunk of size: {size}")

        if size == 1000 + flag:
            received_data += chunk
            flag += 1
            logger.info(f"Added chunk {flag} to received data")
        elif size < 1000 and flag == 6:
            received_data += chunk
            logger.info("Added final chunk to received data")
            break
        else:
            logger.warning(f"Unexpected chunk size: {size}. Ignoring this chunk.")

    logger.info(f"Total received data size: {len(received_data)}")

    with open("received_image.png", "wb") as f:
        f.write(received_data)
    logger.info("Image saved as 'received_image.png'")

except socket.timeout:
    logger.error("Socket operation timed out")
except Exception as e:
    logger.error(f"An error occurred: {e}")
finally:
    client.close()

# Verify the PNG file
try:
    from PIL import Image
    with Image.open("received_image.png") as img:
        img.verify()
    logger.info("PNG file verified successfully")
except Exception as e:
    logger.error(f"Error verifying PNG file: {e}")