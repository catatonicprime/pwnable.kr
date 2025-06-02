#!/usr/bin/env python

import pwn
import os
import tempfile
import random
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

# Stage 5.a
port = random.randrange(30000,65535)

# Stage 1: Setting up all the args
argv = ['']*100
argv[0x41] = b'\x00'
argv[0x42] = b'\x20\x0a\x0d'
argv[0x43] = str(port)

# Stage 4: Creating a working directory
cwd = os.getcwd()
tmpdir = tempfile.mkdtemp()
print(f'Temp directory: {tmpdir}')
os.chdir(tmpdir)
with open(b'\x0a', 'wb') as file:
  file.write(b'\x00\x00\x00\x00')
# Stage "6": Need a symlink to point to the flag
basedir = os.path.dirname(f'{args.filename}')
flagpath = f'{basedir}/flag'
os.symlink(flagpath, 'flag')

# Stage 2: Sending data via stdin/stderr
c = pwn.process(['cat', '-'], stdout=pwn.PIPE)
c.send(b'\x00\x0a\x02\xff')

# Stage 3: Passing environment variables too
p = pwn.process(executable=f'{args.filename}', argv=argv, stderr=c.stdout, env={b'\xde\xad\xbe\xef':b'\xca\xfe\xba\xbe'})
p.send(b'\x00\x0a\x00\xff')

# Stage 5: Connecting to the network socket using the port we passed
conn = pwn.remote('127.0.0.1', port)
conn.send(b'\xde\xad\xbe\xef')
print(p.recvall(timeout=1))

# Cleaning up like mommy taught us
print(f'Cleaning up {tmpdir}')
os.chdir(cwd)
os.remove(f'{tmpdir}/\x0a')
os.remove(f'{tmpdir}/flag')
os.rmdir(f'{tmpdir}')
