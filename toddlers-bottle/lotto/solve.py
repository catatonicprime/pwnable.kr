# Lotto looks like a failure to rate limit, there is a commented out sleep(1)
# So, pick some random bytes, then hammer it till you make it =)

import os
import pwn
import time

import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

print(f"Selected filename: {args.filename}")

myluck = b'\x01\x01\x01\x01\x01\x01'
attempt_count = 0

p = pwn.process(f"{args.filename}")
#p = pwn.process('./lotto')
while(True):
    attempt_count += 1
    p.send(b'1\n')
    p.recvuntil(b'Submit your 6 lotto bytes : ')
    p.send(myluck+b'\n')
    p.recvuntil(b'Lotto Start!\n') # Lotto Start
    output = p.recvuntil(b'\n')
    if b"bad luck" not in output:
        break
print(output)
print(attempt_count)
