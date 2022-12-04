import angr
import pwn
import os


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
project = angr.Project("/home/fd/fd")
project.loader

# Establish a state for solving
state = project.factory.entry_state()

# This respresents the 32-bit integer we have control of.
fd = state.solver.BVS("fd", 32)

# Identify  & establish constraints.
prob = fd - 0x1234 #TODO: Recover this value from the binary under test for future-proofing.

# Solve for constraints.
state.solver.add(prob == 0)
arg = state.solver.eval(fd)

# Report the results.
print("The Solution is: {}".format(arg))

# Set the current working directory & solve using the above result.
os.chdir("/home/fd/")
p = pwn.process(["./fd", str(arg)])
p.sendline('LETMEWIN') #TODO: resolve this string from the strcmp args for future proofing.
print(p.recvall())