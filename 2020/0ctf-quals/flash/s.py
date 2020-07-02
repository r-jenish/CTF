from pwn import *
import ctypes

# flash-1
# flag{it's_time_to_pwn_this_machine!}

bstr = lambda x: x if isinstance(x,bytes) else x.encode()
sstr = lambda x: x if isinstance(x,str) else x.decode()
ehex = lambda b: bstr(b).hex()
dhex = lambda s: bytes.fromhex(sstr(s))
itoa = lambda i: bstr(str(i))

x = dhex("0009091d00090000000a00050006001400090001000a0001000b0008000900010006ffe00009001100020009b2480003000972a90005000701440009001100020009b24800030009097e00050007012e0009001100020009b2480003000955600005000701180009001100020009b248000300094ca10005000701020009001100020009b2480003000900370005000700ec0009001100020009b24800030009aa710005000700d60009001100020009b24800030009122c0005000700c00009001100020009b2480003000945360005000700aa0009001100020009b2480003000911e80005000700940009001100020009b24800030009124700050007007e0009001100020009b2480003000976c70005000700680009001100020009b24800030009096d0005000700520009001100020009b24800030009122c00050007003c0009001100020009b2480003000987cb0005000700260009001100020009b2480003000909e40005000700100009091d0007000800090000000b000d00090001000b000d")

l = list(map(lambda z: u16(z,endianness='big'),[x[i:i+2] for i in range(0, len(x), 2)]))

i = 0

def goff(k,j):
    if ctypes.c_int16(j).value < 0:
        return ctypes.c_int16(k+((j+1)&0xfffe)).value
    else:
        return ctypes.c_int16(k+(j&0xfffe)).value

while (i/2) < len(l):
    t = l[int(i/2)]
    j = i
    i += 2
    if t == 0:
        print("0x%04x : add" % j)
    elif t == 1:
        print("0x%04x : sub" % j)
    elif t == 2:
        print("0x%04x : mul" % j)
    elif t == 3:
        print("0x%04x : mod" % j)
    elif t == 4:
        print("0x%04x : setle" % j)
    elif t == 5:
        print("0x%04x : seteq" % j)
    elif t == 6:
        print("0x%04x : jnez 0x%x" % (j,goff(i+2,l[int(i/2)])))
        i += 2
    elif t == 7:
        print("0x%04x : jeqz 0x%x" % (j,goff(i+2,l[int(i/2)])))
        i += 2
    elif t == 8:
        print("0x%04x : push <flag_2b>" % j)
    elif t == 9:
        print("0x%04x : push 0x%x" % (j,l[int(i/2)]))
        i += 2
    elif t == 10:
        print("0x%04x : push acc" % j)
    elif t == 11:
        print("0x%04x : pop acc" % j)
    elif t == 12:
        print("0x%04x : pop" % j)
    elif t == 13:
        print("0x%04x : ret acc" % j)
