import angr
import claripy
from pwnlib.util.packing import pack, flat
import argparse

"""
Walk through:
1. Review ~/passcode.c
2. Note: three primary input components
    a. 100 byte string for name on welcome
    b. code1 & code2
    c. code1 & code2 are compared to values
3. if strcmp of buf matches input then win.
"""

# Load the binary for analysis.
proj = angr.Project("./passcode")
proj.loader
cfg = proj.analyses.CFGEmulated()
target_func = cfg.functions['login']

# Establish a state for solving
codes = claripy.BVS('stdin', 20*8) # Create 20 bytes of bitvector


state = proj.factory.entry_state(addr=target_func.addr, args=[], stdin=angr.SimFileStream(name='stdin', content=codes, has_end=False)) # This works too!
#state = proj.factory.entry_state(addr=start.addr, args=['./fd', passcode], stdin=angr.SimFileStream(name='stdin', content=letmewin, has_end=False))

constraints = []

# # Add constraints on inputs to ensure alpha-only characters are used.
# for byte in passcode.chop(bits=8):
#     constraints.append(byte >= 0x30) # minimum value
#     constraints.append(byte <= 0x39) # maximum value


# # Add all the constraints to the solver.
# for constraint in constraints:
#     state.solver.add(constraint)

# Create a simulation mamanger & find a path to the target.
simgr = proj.factory.simgr(state)
simgr.explore(find=0x080485d7, avoid=[0x0485f1])

pathcount = len(simgr.found)
print("Length simgr.found: {}".format(pathcount))
if pathcount == 0:
    exit()

# Show the solution!
solution = simgr.found[0]
print(solution.solver.eval(codes, cast_to=bytes))
