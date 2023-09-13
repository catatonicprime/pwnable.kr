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
cfg = proj.analyses.CFGEmulated()
main = cfg.kb.functions["main"]

# Establish a state for solving
passcode = claripy.BVS('passcode', 20*8) # Create 20 bytes of bitvector
# state = proj.factory.entry_state(addr=main.addr, args=['col', passcode])
state = proj.factory.entry_state(addr=main.addr, args=['./col', passcode])

constraints = []

constraints.append(state.posix.argc == 0x02)
# constraints.append(passcode[8:0] == 0x62)
# constraints.append(passcode[16:8] == 0x78)
# constraints.append(passcode[24:16] == 0x4a)


block_ranges = [(0x3a, 0x40), (0x5b, 0x60)]
for i in range(20):
    if i == 19:
        constraints.append(passcode[:i*8] >= 0x4a)
        constraints.append(passcode[:i*8] <= 0x7a)
        for block_range in block_ranges:
            for to_block  in range(block_range[0], block_range[1]+1):
                constraints.append(passcode[:i*8] != to_block)
    else:
        constraints.append(passcode[i*8+8:i*8] >= 0x4a)
        constraints.append(passcode[i*8+8:i*8] <= 0x7a)
        for block_range in block_ranges:
            for to_block  in range(block_range[0], block_range[1]+1):
                constraints.append(passcode[i*8+8:i*8] != to_block)

for constraint in constraints:
    state.solver.add(constraint)

simgr = proj.factory.simgr(state)

simgr.explore(find=[0x0804856e], avoid=[0x08048581, 0x08048508, 0x08048540])

print("Length simgr.found: {}".format(len(simgr.found)))
solution = simgr.found[0]
arg1 = solution.solver.eval(passcode, cast_to=bytes)
print(arg1)