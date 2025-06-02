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

Early attempts to solve this using angr resulted in minor errors.
1. Angr is not environmentally aware, so it makes guesses about
   things like open files. A read() of an open file, which angr
   automatically creates, with a file handle that computes to the
   fd of the simfile - will satisfy this problem.
2. Symbolically this is still correct. But concretely it needs a
   little help. So we opt to catch the result of atoi() and
   constraint it to 0x00.
"""

# Load the binary for analysis.
proj = angr.Project("./fd")
proj.loader
# cfg = proj.analyses.CFGEmulated()
# start = cfg.functions['_start']

# Establish a state for solving
passcode = claripy.BVS('passcode', 20*8)
state_atoi = proj.factory.full_init_state(args=['./fd', passcode])
 
sim_atoi = proj.factory.simgr(state_atoi)
atoi_result = sim_atoi.explore(find=[0x080484d0], avoid=[0x080484a5])
assert len(atoi_result.found) > 0

atoi_result.found[0].solver.add(atoi_result.found[0].regs.eax == 0x00)
sim_stdin = proj.factory.simgr(atoi_result.found[0])
sim_stdin.explore(find=[0x08048524], avoid=[0x08048548])

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
solution = sim_stdin.found[0]
print(solution.solver.eval(passcode, cast_to=bytes))
print(solution.posix.stdin.concretize())
