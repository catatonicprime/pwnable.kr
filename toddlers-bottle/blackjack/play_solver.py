#!/usr/bin/env python

# This solver also cheats, but no so blatantly. Abuses the srand. Still loses sometimes, of course ;-)
import pwn
import time
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", nargs='?', type=str, help="The name of the file to process")
args = parser.parse_args()

target_cash = 10**6

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
      if cash > target_cash:
        break
      if cash < 50:
          conn.close()
    if b'Your Total is ' in line:
      hand = int(line.split(b' ')[3])
      if needbet:
        hand_base = hand
    if b'The Dealer Has a Total of ' in line:
      dealer = int(line.split(b' ')[6])
      if needbet:
        dealer_base = dealer
      t = time.perf_counter()
      scalar = 1 - (t - int(t)) # so 99 scales down to near 0 because the rng is about to roll over.
      bet = int(scalar * cash) if hand_base in [3, 7] and dealer_base not in [3, 7] or hand_base == 7 and dealer_base != 7 else 0
      if needbet:
        needbet = False
        print(f'Betting: {bet}')
        conn.sendline(str(bet))
    if b'Please Enter H to Hit or S to Stay.' in line:
      print(f'Cash: {cash}  Game: Hand Base {hand_base} / Hand {hand} vs. Dealer {dealer}')
      if hand_base in [3, 7] and dealer not in [1, 3, 7] or hand <= dealer: # Keep hitting on 1, 3, 7 to make 21 and win, but don't play against winning dealers.
        #print(f'Hitting')
        conn.sendline(b'H')
      else:
        if dealer in [1, 3, 7]:
          time.sleep(1) # stifle the dealer
        #print(f'Staying')
        conn.sendline(b'S')
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

