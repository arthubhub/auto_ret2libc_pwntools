from pwn import ELF, process, ROP, remote, ssh, gdb, cyclic, cyclic_find, log, p64, u64  # Import pwntools


## Steps :
# 1) Find the offset of BOF -> (Go to vulnerable input, send cyclic datas, wait for crashing and get back the offset) 
# 2) Find the LIBC version -> (leak a function address, get the LSB of this address, use an external tool to detect the version)
# 3) Calculate offset between remote libc leaked address and useful values (/bin/sh, system)
# 4) Final exploit : BOF -> leak aslr -> calculate offsets -> system(/bin/sh)




#######################
### LOCAL ANALYSIS ####
#######################

LOCAL = True
GDB = False
LOCAL_BIN = "./exploitable"

LIBC = "" #ELF("/lib/x86_64-linux-gnu/libc.so.6") #Set library path when know it
ENV = {"LD_PRELOAD": LIBC} if LIBC else {}

# Extract static datas
ELF_LOADED = ELF(LOCAL_BIN)# Extract data from binary
ROP_LOADED = ROP(ELF_LOADED)# Find ROP gadgets

