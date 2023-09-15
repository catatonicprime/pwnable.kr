import angr
import pwn
from pwnlib.util.packing import pack


"""
Walk through:
1. Review ~/col.c
2. Note: single input component, 'passcode'
    a. printable chars preferable (for easy typing), say between 0x30 and 0x7a
    b. argv[1] must be 20 bytes, or 5x 4 byte ints - say I0-I4 (integers) with constraints
       on each of the bytes for the printable chars in 2.a
    c. sum of 4 byte ints matches value in 'hashcode'

Example Usage:
    cd ~; python /tmp/solver.py
"""

def print_solution(state, ints):
    # Solve
    solution = ""
    for integer in ints:
        ix = state.solver.eval(integer)
        solution += pack(ix, 32, 'little', True).decode()
    print("A solution is: {}".format(solution))

# Load the binary for analysis. We can use any binary because
# this solver only uses the angr state machine to solve an
# abstract represenation. 
project = angr.Project("./col")
project.loader

# Establish a state for solving
state = project.factory.entry_state()

constraints = []
# Now that we have all our bytes in printable, lets try combining them into ints.
ints = []
for i in range(5):
    # Create a new int
    isym = state.solver.BVS("I{}".format(i), 32)
    ints.append(isym)
    # Add our printable character constraints for each integer
    block_ranges = [(0x3a, 0x41), (0x5b, 0x61)]
    for shift in range(4):
        # Block lists
        # Something interesting to me happens here... 
        # I'm not sure you can add a block using ranges.
        # I think you must enumerate them?
        # m, n are ordered; m is always the "lesser" of the two values.
        #   [set to allow]m[set to block]n[set to allow]: constraint > n | constraint <= m, the | requires two (contradictory) constraints
        # You cannot set a value to be both bigger than n AND lesser or equal to m as m is always ther lesser of m & n.
        # Perhaps the inverse is better:
        #   [set to block]m[set to allow]n[set to block]: constraint <= n & constraint > m, this works in this scenario, but consider
        # It breaks down if you add another allowd block at the end. Feel like
        #  there's probably some simple set math that demonstrates this.
        for block_range in block_ranges:
            for to_block  in range(block_range[0], block_range[1]):
                constraint = isym & (0xFF << (shift * 8)) != (to_block << (shift * 8))
                constraints.append(constraint)

        # Allowed list
        constraint = isym & (0xFF << (shift * 8)) >= (0x4a << (shift * 8))
        constraints.append(constraint)
        constraint = isym & (0xFF << (shift * 8)) <= (0x7a << (shift * 8))
        constraints.append(constraint)


# Now for the hashcode problem constraint
prob = (ints[0] + ints[1] + ints[2] + ints[3] + ints[4]) == 0x21DD09EC # 568134124 in dec
constraints.append(prob)

# Apply all constraints
for constraint in constraints:
    state.solver.add(constraint)

print_solution(state, ints)

constraints.append(constraint)

# p = pwn.process(["./col", solution])
# print(p.recvall())