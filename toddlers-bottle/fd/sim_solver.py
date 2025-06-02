#!/usr/bin/env python
import angr
import claripy
import pwn
import os
import argparse

parser = argparse.ArgumentParser(description='Select a filename.')
parser.add_argument('filename', type=str, help='The name of the file to process')
args= parser.parse_args()

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
proj = angr.Project(f'{args.filename}', auto_load_libs=False)
proj.loader

cfg = proj.analyses.CFGEmulated()
read_addr = [addr for addr, func in cfg.kb.functions.items() if 'read' == func.name and func.is_plt][0]

def read_check(state):
    if state.ip.args[0] == read_addr:
        return True

# Establish a state for solving
arg1_list = [claripy.BVS(f'arg1_0', 8)]
arg1 = arg1_list[-1]
for i in range(1,11):
    arg1_list.append(claripy.BVS(f'arg1_{i}', 8))
    arg1 = arg1.concat(arg1_list[-1])

state = proj.factory.entry_state(addr=cfg.functions['_start'].addr, args=[f'{args.filename}', arg1]) # 11 bytes for atoi
simgr = proj.factory.simulation_manager(state)

# Find a state that is at the read
simgr.explore(find=read_check)

if len(simgr.found) == 0:
    print("No paths found")
    exit(-1)

found = simgr.found[0]

# Constrain the first argument to read to be 0 based on calling convention used:
read_convention = [func.calling_convention for addr, func in cfg.kb.functions.items() if 'read' == func.name and not func.is_plt][0]
if isinstance(read_convention, angr.calling_conventions.SimCCSystemVAMD64):
    # first argument is stored in RDI
    found.add_constraints(found.regs.rdi == 0)
elif isinstance(read_convention, angr.calling_conventions.SimCCCdecl):
    # first argument is stored on stack
    found.add_constraints(found.memory.load(found.regs.ebp.args[0] - 0x1c, 2) == 0)# "push DWORD PTR [ebp-0x1c]" immediately prior to read call
else:
    print('Unknown calling convention, you\'re on your own!')
    exit(-2)

simgr.explore(find=read_check)

if len(simgr.found) == 0:
    print("No constrained paths found")
    exit(-1)

solution = ''.join([chr(simgr.found[0].solver.eval(arg1_byte)) for arg1_byte in arg1_list])
print(f'''
import pwn
p = pwn.process(['{args.filename}', '{solution}'])
p.sendline('LETMEWIN')
print(p.recvall().decode('utf-8'))
p.close()
''')
