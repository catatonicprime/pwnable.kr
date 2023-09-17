import angr
import claripy
from pwnlib.util.packing import pack, flat
import argparse

"""
Walk through:
1. Review ~/fd.c
2. Note: two primary input components
    a. argv[1] (first argument) read as an int and stored in 'fd'
    b. buf is a string read from 'fd'
    c. buf should be read from stdin (when fd equals 0)
3. if strcmp of buf matches input then win.
"""

# Load the binary for analysis.
proj = angr.Project("./files/fd")
proj.loader
# cfg = proj.analyses.CFGEmulated()
# start = cfg.functions['_start']

# Establish a state for solving
passcode = claripy.BVS('passcode', 4*8)

state = proj.factory.full_init_state(args=['./fd', passcode])

constraints = []
# constraints.append(passcode.chop(bits=8)[3] == 0x30)

# Add constraints on inputs to ensure alpha-only characters are used.
# for byte in passcode.chop(bits=8):
#     constraints.append(byte >= 0x30) # minimum value
#     constraints.append(byte <= 0x39) # maximum value


# Add all the constraints to the solver.
for constraint in constraints:
    state.solver.add(constraint)

simgr = proj.factory.simgr(state)
simgr.explore(find=[0x08048524], avoid=[0x08048548, 0x080484a5])

pathcount = len(simgr.found)
print("Length simgr.found: {}".format(pathcount))
if pathcount == 0:
    exit()

# Show the solution!
solution = simgr.found[0]
print(solution.solver.eval(passcode, cast_to=bytes))
simfile = solution.posix.get_fd(3)
data, actual_size, new_pos = simfile.file.read(0, simfile.file.size)
print(solution.solver.eval(data, cast_to=bytes))


# Create a simulation mamanger & find a path to the target.

