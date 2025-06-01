#!/usr/bin/env python

import angr
import claripy
from pwnlib.util.packing import pack, flat
import argparse

parser = argparse.ArgumentParser(description='Configure analysis')
parser.add_argument('filename', type=str, help='The name of the file to process')
parser.add_argument('-a', '--alpha-only',
                    dest='alpha_only',
                    action=argparse.BooleanOptionalAction,
                    type=bool,
                    help='limit solutions to upper/lower case letters only')
args = parser.parse_args()


"""
Walk through:
1. Review ~/col.c
2. Note: single input component, 'passcode'
    a. printable chars preferable (for easy typing), say between 0x30 and 0x7a
    b. argv[1] must be 20 bytes, or 160 bits
    c. sum of 4 byte ints matches value in 'hashcode'
3. Try using the simulator to explore/find the path.
"""

# Load the binary for analysis.
proj = angr.Project(f'{args.filename}', auto_load_libs=False)
proj.loader
cfg = proj.analyses.CFGEmulated()
start = cfg.functions['_start']

# Establish a state for solving
passcode = claripy.BVS('passcode', 20*8) # Create 20 bytes of bitvector
state = proj.factory.entry_state(addr=start.addr, args=[f'{args.filename}', passcode])

constraints = []
constraints.append(state.posix.argc == 0x02)

if args.alpha_only:
    # Add constraints on inputs to ensure alpha-only characters are used.
    for byte in passcode.chop(bits=8):
        constraints.append(byte >= 0x41)
        constraints.append(byte <= 0x7a)

        # And what we want to restrict for each byte of passcode
        block_ranges = [(0x3a, 0x41), (0x5b, 0x61)]
        for block_range in block_ranges:
            for to_block  in range(block_range[0], block_range[1]):
                constraints.append(byte != to_block)

# Add all the constraints to the solver.
for constraint in constraints:
    state.solver.add(constraint)

# Create a simulation mamanger & find a path to the target.
simgr = proj.factory.simgr(state)
main = cfg.functions['main'].addr
simgr.explore(find=[main+151], avoid=[main+37, main+96, main+201])

pathcount = len(simgr.found)
print("Length simgr.found: {}".format(pathcount))
if pathcount == 0:
    exit()

# Show the solution!
solution = simgr.found[0]
arg1 = solution.solver.eval(passcode, cast_to=bytes)
print(arg1)
