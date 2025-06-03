#!/usr/bin/env python
import pwn
import itertools
import random

def search(conn, stack):
  stacks = [[],[]]
  for i, v in enumerate(stack):
    stacks[i % 2].append(v)
  weigh = ' '.join(stacks[0]).encode('utf-8')
  conn.sendline(weigh)
  weightline = conn.recvline()
  if b'Correct' in weightline:
      return
  weight = int(weightline)
  if weight < len(stacks[0]) * 10:
    search(conn, stacks[0])
  else:
    search(conn, stacks[1])

conn = pwn.remote('127.0.0.1', 9007)
conn.recvuntil(b'starting in 3 sec...')

loop = 11
while(loop > 0):
  line = conn.recvline()
  print(line)
  if line.startswith(b'N='):
    parsed = [arg.split(b'=')[1] for arg in line.split(b' ')]
    stack = [str(i) for i in range(int(parsed[0]))] # Create a stack of N coins
    random.shuffle(stack) # Just for fun =)
    search(conn, stack)
