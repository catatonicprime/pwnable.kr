import angr
import claripy
from pwnlib.util.packing import pack, flat


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
proj = angr.Project("./col")
proj.loader

# Establish a state for solving
passcode = claripy.BVS('passcode', 20*8) # Create 20 bytes of bitvector
state = proj.factory.full_init_state(args=['./col', passcode])

constraints = []
constraints.append(state.posix.argc == 0x02)

# Expected constraints on inputs to ensure alpha-only characters are used.
block_ranges = [(0x3a, 0x40), (0x5b, 0x60)]
for byte in passcode.chop(bits=8):
    constraints.append(byte >= 0x4a)
    constraints.append(byte <= 0x7a)
    for block_range in block_ranges:
        for to_block  in range(block_range[0], block_range[1]+1):
            constraints.append(byte != to_block)

# Add all the constraints to the solver.
for constraint in constraints:
    state.solver.add(constraint)

# Create a simulation mamanger & find a path to the target.
simgr = proj.factory.simgr(state)
simgr.explore(find=[0x0804856e], avoid=[0x08048581, 0x08048508, 0x08048540])

pathcount = len(simgr.found)
print("Length simgr.found: {}".format(pathcount))
if pathcount == 0:
    exit()

# Show the solution!
solution = simgr.found[0]
arg1 = solution.solver.eval(passcode, cast_to=bytes)
print(arg1)