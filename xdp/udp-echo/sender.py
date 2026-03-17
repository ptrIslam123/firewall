#!/usr/bin/env python3
import socket
import argparse

parser = argparse.ArgumentParser(description='Простая отправка UDP')
parser.add_argument('--interface', '-I', help="Сетевой интерфейс с которого будет отправле пакет")
parser.add_argument('--dst-ip', '-dip', required=True, help='IP адрес получателя')
parser.add_argument('--dst-port', '-dp', type=int, default=12345, help='Порт назначения')

args = parser.parse_args()

message = "Hello world!"
src_port = 54321
dst_ip = args.dst_ip
dst_port = args.dst_port
interface= args.interface

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if interface != str():
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
        print(f"📡 Bind socket to interface={interface}")

    sock.bind(('0.0.0.0', src_port))

    sock.sendto(message.encode(), (dst_ip, dst_port))
    print(f"✅ UDP пакет отправлен на {dst_ip}:{dst_port}")
    
    
    sock.settimeout(10)
    response, addr = sock.recvfrom(1024)
    
    print(f"response={response} from={addr}")
    
except Exception as e:
    print(f"❌ Ошибка: {e}")
finally:
    sock.close()