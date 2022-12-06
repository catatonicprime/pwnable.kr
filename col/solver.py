import angr
import pwn
from pwnlib.util.packing import pack
import os


"""
Walk through:
1. Review ~/col.c
2. Note: single input component, 'passcode'
    a. printable chars preferable (for easy typing), say between 0x30 and 0x7a
    b. argv[1] must be 20 bytes, or 5x 4 byte ints - say I0-I4 (integers) with constraints
       on each of the bytes for the printable chars in 2.a
    c. sum of 4 byte ints matches value in 'hashcode'
"""
# Set the current working directory & solve using the above result.
os.chdir("/home/col/")

# Load the binary for analysis.
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
    for shift in range(4):
        constraint = isym & (0xFF << (shift * 8)) >= (0x30 << (shift * 8))
        constraints.append(constraint)
        constraint = isym & (0xFF << (shift * 8)) <= (0x7a << (shift * 8))
        constraints.append(constraint)


# Now for the hashcode problem constraint
prob = (ints[0] + ints[1] + ints[2] + ints[3] + ints[4]) == 0x21DD09EC # 568134124 in dec
constraints.append(prob)

# Apply all constraints
for constraint in constraints:
    state.solver.add(constraint)

# Solve
solution = ''
for integer in ints:
    ix = state.solver.eval(integer)
    solution += pack(ix, 32, 'little', True)
print("A solution is: {}".format(solution))

p = pwn.process(["./col", solution])
print(p.recvall())