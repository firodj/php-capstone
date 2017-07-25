--TEST--
Capstone Test
--INI--
--FILE--
<?php

$X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00\x8f\xe8\x60\xcd\xe2\x07";
$X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6";
$X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6";

$ARM_CODE     = "";
$ARM_CODE2    = "";
$ARMV8        = "";
$THUMB_MCLASS = "";
$THUMB_CODE   = "";
$THUMB_CODE2  = "";

$MIPS_CODE  = "";
$MIPS_CODE2 = "";
$MIPS_32R6M = "";
$MIPS_32R6  = "";

$ARM64_CODE   = "";
$PPC_CODE     = "";
$SPARC_CODE   = "";
$SPARCV9_CODE = "";
$SYSZ_CODE    = "";
$XCORE_CODE   = "";

require 'fixture.inc';

foreach($platforms as $platform) {
    if ($platform[0] != CS_ARCH_X86) continue;

    printf("****************\n");
    printf("Platform: %s\n", $platform[3]);
    $handle = cs_open($platform[0], $platform[1]);
    if (!$handle) continue;

    if (isset($platform[4])) {
        cs_option($handle, $platform[4], $platform[5]);
    }
    cs_option($handle, CS_OPT_DETAIL, CS_OPT_ON);

    printf("Code: %s\n", string_hex($platform[2]));

    printf("Disasm:\n");
    $insn = cs_disasm($handle, $platform[2], 0x1000);

    foreach ($insn as $ins) {
        print_ins($ins);

        $x86 = &$ins->detail->x86;
        print_x86_detail($x86);

        printf("\n");
    }

    printf("0x%x:\n", $ins->address + count($ins->bytes));
    printf("\n");

    cs_close($handle);
}
--EXPECT--
****************
Platform: X86 16bit (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x05 0x23 0x01 0x00 0x00 0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00 0x41 0x8d 0x84 0x39 0x89 0x67 0x00 0x00 0x8d 0x87 0x89 0x67 0x00 0x00 0xb4 0xc6
Disasm:
0x1000:	lea		cx, [si + 0x32]
bytes:	0x8d 0x4c 0x32
	size: 3
	opcode: 0x8d
	rex: 0x0
	addr_size: 2
	modrm: 0x4c
	disp: 0x32
	eflags:
	op_count: 2
		operands[0].type: reg = cx
		operands[0].size: 2
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.base: reg = si
			operands[1].mem.disp: 0x32
		operands[1].size: 2
		operands[1].access: read

0x1003:	or		byte ptr [bx + di], al
bytes:	0x08 0x01
	size: 2
	registers modified: flags
	opcode: 0x08
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	disp: 0x0
	eflags:
		modify: sf zf pf
		reset: of cf
		undefined: af
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = bx
			operands[0].mem.index: reg = di
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: reg = al
		operands[1].size: 1
		operands[1].access: read

0x1005:	fadd		dword ptr [bx + di + 0x34c6]
bytes:	0xd8 0x81 0xc6 0x34
	size: 4
	registers modified: fpsw
	instructions groups: fpu
	opcode: 0xd8
	rex: 0x0
	addr_size: 2
	modrm: 0x81
	disp: 0x34c6
	eflags:
		modify: cf
		prior: sf af pf
	op_count: 1
		operands[0].type: mem
			operands[0].mem.base: reg = bx
			operands[0].mem.index: reg = di
			operands[0].mem.disp: 0x34c6
		operands[0].size: 4
		operands[0].access: read

0x1009:	adc		al, byte ptr [bx + si]
bytes:	0x12 0x00
	size: 2
	registers read: flags
	registers modified: flags
	opcode: 0x12
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: reg = al
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: mem
			operands[1].mem.base: reg = bx
			operands[1].mem.index: reg = si
		operands[1].size: 1
		operands[1].access: read

0x100b:	add		byte ptr [di], al
bytes:	0x00 0x05
	size: 2
	registers modified: flags
	opcode: 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x5
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = di
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: reg = al
		operands[1].size: 1
		operands[1].access: read

0x100d:	and		ax, word ptr [bx + di]
bytes:	0x23 0x01
	size: 2
	registers modified: flags
	opcode: 0x23
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	disp: 0x0
	eflags:
		modify: sf zf pf
		reset: of cf
		undefined: af
	op_count: 2
		operands[0].type: reg = ax
		operands[0].size: 2
		operands[0].access: read | write
		operands[1].type: mem
			operands[1].mem.base: reg = bx
			operands[1].mem.index: reg = di
		operands[1].size: 2
		operands[1].access: read

0x100f:	add		byte ptr [bx + si], al
bytes:	0x00 0x00
	size: 2
	registers modified: flags
	opcode: 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = bx
			operands[0].mem.index: reg = si
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: reg = al
		operands[1].size: 1
		operands[1].access: read

0x1011:	mov		ax, word ptr ss:[si + 0x2391]
bytes:	0x36 0x8b 0x84 0x91 0x23
	size: 5
	prefix: ss
	opcode: 0x8b
	rex: 0x0
	addr_size: 2
	modrm: 0x84
	disp: 0x2391
	eflags:
	op_count: 2
		operands[0].type: reg = ax
		operands[0].size: 2
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.segment: reg = ss
			operands[1].mem.base: reg = si
			operands[1].mem.disp: 0x2391
		operands[1].size: 2
		operands[1].access: read

0x1016:	add		word ptr [bx + si], ax
bytes:	0x01 0x00
	size: 2
	registers modified: flags
	opcode: 0x01
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = bx
			operands[0].mem.index: reg = si
		operands[0].size: 2
		operands[0].access: read | write
		operands[1].type: reg = ax
		operands[1].size: 2
		operands[1].access: read

0x1018:	add		byte ptr [bx + di - 0x73], al
bytes:	0x00 0x41 0x8d
	size: 3
	registers modified: flags
	opcode: 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x41
	disp: 0xffffffffffffff8d
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = bx
			operands[0].mem.index: reg = di
			operands[0].mem.disp: 0xffffffffffffff8d
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: reg = al
		operands[1].size: 1
		operands[1].access: read

0x101b:	test		byte ptr [bx + di], bh
bytes:	0x84 0x39
	size: 2
	registers modified: flags
	opcode: 0x84
	rex: 0x0
	addr_size: 2
	modrm: 0x39
	disp: 0x0
	eflags:
		modify: sf zf pf
		reset: of cf
		undefined: af
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = bx
			operands[0].mem.index: reg = di
		operands[0].size: 1
		operands[0].access: read
		operands[1].type: reg = bh
		operands[1].size: 1
		operands[1].access: read

0x101d:	mov		word ptr [bx], sp
bytes:	0x89 0x67 0x00
	size: 3
	opcode: 0x89
	rex: 0x0
	addr_size: 2
	modrm: 0x67
	disp: 0x0
	eflags:
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = bx
		operands[0].size: 2
		operands[0].access: write
		operands[1].type: reg = sp
		operands[1].size: 2
		operands[1].access: read

0x1020:	add		byte ptr [di - 0x7679], cl
bytes:	0x00 0x8d 0x87 0x89
	size: 4
	registers modified: flags
	opcode: 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x8d
	disp: 0xffffffffffff8987
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = di
			operands[0].mem.disp: 0xffffffffffff8987
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: reg = cl
		operands[1].size: 1
		operands[1].access: read

0x1024:	add		byte ptr [eax], al
bytes:	0x67 0x00 0x00
	size: 3
	registers modified: flags
	prefix: addrsize
	opcode: 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = eax
		operands[0].size: 1
		operands[0].access: read | write
		operands[1].type: reg = al
		operands[1].size: 1
		operands[1].access: read

0x1027:	mov		ah, 0xc6
bytes:	0xb4 0xc6
	size: 2
	opcode: 0xb4
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	eflags:
	op_count: 2
		operands[0].type: reg = ah
		operands[0].size: 1
		operands[0].access: write
		operands[1].type: imm = 0xc6
		operands[1].size: 1

0x1029:

****************
Platform: X86 32bit (ATT syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x05 0x23 0x01 0x00 0x00 0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00 0x41 0x8d 0x84 0x39 0x89 0x67 0x00 0x00 0x8d 0x87 0x89 0x67 0x00 0x00 0xb4 0xc6
Disasm:
0x1000:	leal		8(%edx, %esi), %ecx
bytes:	0x8d 0x4c 0x32 0x08
	size: 4
	instructions groups: not64bitmode
	opcode: 0x8d
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	disp: 0x8
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	eflags:
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = edx
			operands[0].mem.index: reg = esi
			operands[0].mem.disp: 0x8
		operands[0].size: 4
		operands[0].access: read
		operands[1].type: reg = ecx
		operands[1].size: 4
		operands[1].access: write

0x1004:	addl		%ebx, %eax
bytes:	0x01 0xd8
	size: 2
	registers modified: eflags
	opcode: 0x01
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: reg = ebx
		operands[0].size: 4
		operands[0].access: read
		operands[1].type: reg = eax
		operands[1].size: 4
		operands[1].access: read | write

0x1006:	addl		$0x1234, %esi
bytes:	0x81 0xc6 0x34 0x12 0x00 0x00
	size: 6
	registers modified: eflags
	opcode: 0x81
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: imm = 0x1234
		operands[0].size: 4
		operands[1].type: reg = esi
		operands[1].size: 4
		operands[1].access: read | write

0x100c:	addl		$0x123, %eax
bytes:	0x05 0x23 0x01 0x00 0x00
	size: 5
	registers modified: eflags
	opcode: 0x05
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: imm = 0x123
		operands[0].size: 4
		operands[1].type: reg = eax
		operands[1].size: 4
		operands[1].access: read | write

0x1011:	movl		%ss:0x123(%ecx, %edx, 4), %eax
bytes:	0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00
	size: 8
	prefix: ss
	opcode: 0x8b
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	disp: 0x123
	sib: 0x91
		sib_base: ecx
		sib_index: edx
		sib_scale: 4
	eflags:
	op_count: 2
		operands[0].type: mem
			operands[0].mem.segment: reg = ss
			operands[0].mem.base: reg = ecx
			operands[0].mem.index: reg = edx
			operands[0].mem.scale: 4
			operands[0].mem.disp: 0x123
		operands[0].size: 4
		operands[0].access: read
		operands[1].type: reg = eax
		operands[1].size: 4
		operands[1].access: write

0x1019:	incl		%ecx
bytes:	0x41
	size: 1
	registers modified: eflags
	instructions groups: not64bitmode
	opcode: 0x41
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af sf zf pf of
	op_count: 1
		operands[0].type: reg = ecx
		operands[0].size: 4
		operands[0].access: read | write

0x101a:	leal		0x6789(%ecx, %edi), %eax
bytes:	0x8d 0x84 0x39 0x89 0x67 0x00 0x00
	size: 7
	instructions groups: not64bitmode
	opcode: 0x8d
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	disp: 0x6789
	sib: 0x39
		sib_base: ecx
		sib_index: edi
		sib_scale: 1
	eflags:
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = ecx
			operands[0].mem.index: reg = edi
			operands[0].mem.disp: 0x6789
		operands[0].size: 4
		operands[0].access: read
		operands[1].type: reg = eax
		operands[1].size: 4
		operands[1].access: write

0x1021:	leal		0x6789(%edi), %eax
bytes:	0x8d 0x87 0x89 0x67 0x00 0x00
	size: 6
	instructions groups: not64bitmode
	opcode: 0x8d
	rex: 0x0
	addr_size: 4
	modrm: 0x87
	disp: 0x6789
	eflags:
	op_count: 2
		operands[0].type: mem
			operands[0].mem.base: reg = edi
			operands[0].mem.disp: 0x6789
		operands[0].size: 4
		operands[0].access: read
		operands[1].type: reg = eax
		operands[1].size: 4
		operands[1].access: write

0x1027:	movb		$0xc6, %ah
bytes:	0xb4 0xc6
	size: 2
	opcode: 0xb4
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
	op_count: 2
		operands[0].type: imm = 0xc6
		operands[0].size: 1
		operands[1].type: reg = ah
		operands[1].size: 1
		operands[1].access: write

0x1029:

****************
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 0x05 0x23 0x01 0x00 0x00 0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00 0x41 0x8d 0x84 0x39 0x89 0x67 0x00 0x00 0x8d 0x87 0x89 0x67 0x00 0x00 0xb4 0xc6
Disasm:
0x1000:	lea		ecx, [edx + esi + 8]
bytes:	0x8d 0x4c 0x32 0x08
	size: 4
	instructions groups: not64bitmode
	opcode: 0x8d
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	disp: 0x8
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	eflags:
	op_count: 2
		operands[0].type: reg = ecx
		operands[0].size: 4
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.base: reg = edx
			operands[1].mem.index: reg = esi
			operands[1].mem.disp: 0x8
		operands[1].size: 4
		operands[1].access: read

0x1004:	add		eax, ebx
bytes:	0x01 0xd8
	size: 2
	registers modified: eflags
	opcode: 0x01
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: reg = eax
		operands[0].size: 4
		operands[0].access: read | write
		operands[1].type: reg = ebx
		operands[1].size: 4
		operands[1].access: read

0x1006:	add		esi, 0x1234
bytes:	0x81 0xc6 0x34 0x12 0x00 0x00
	size: 6
	registers modified: eflags
	opcode: 0x81
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: reg = esi
		operands[0].size: 4
		operands[0].access: read | write
		operands[1].type: imm = 0x1234
		operands[1].size: 4

0x100c:	add		eax, 0x123
bytes:	0x05 0x23 0x01 0x00 0x00
	size: 5
	registers modified: eflags
	opcode: 0x05
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af cf sf zf pf of
	op_count: 2
		operands[0].type: reg = eax
		operands[0].size: 4
		operands[0].access: read | write
		operands[1].type: imm = 0x123
		operands[1].size: 4

0x1011:	mov		eax, dword ptr ss:[ecx + edx*4 + 0x123]
bytes:	0x36 0x8b 0x84 0x91 0x23 0x01 0x00 0x00
	size: 8
	prefix: ss
	opcode: 0x8b
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	disp: 0x123
	sib: 0x91
		sib_base: ecx
		sib_index: edx
		sib_scale: 4
	eflags:
	op_count: 2
		operands[0].type: reg = eax
		operands[0].size: 4
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.segment: reg = ss
			operands[1].mem.base: reg = ecx
			operands[1].mem.index: reg = edx
			operands[1].mem.scale: 4
			operands[1].mem.disp: 0x123
		operands[1].size: 4
		operands[1].access: read

0x1019:	inc		ecx
bytes:	0x41
	size: 1
	registers modified: eflags
	instructions groups: not64bitmode
	opcode: 0x41
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
		modify: af sf zf pf of
	op_count: 1
		operands[0].type: reg = ecx
		operands[0].size: 4
		operands[0].access: read | write

0x101a:	lea		eax, [ecx + edi + 0x6789]
bytes:	0x8d 0x84 0x39 0x89 0x67 0x00 0x00
	size: 7
	instructions groups: not64bitmode
	opcode: 0x8d
	rex: 0x0
	addr_size: 4
	modrm: 0x84
	disp: 0x6789
	sib: 0x39
		sib_base: ecx
		sib_index: edi
		sib_scale: 1
	eflags:
	op_count: 2
		operands[0].type: reg = eax
		operands[0].size: 4
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.base: reg = ecx
			operands[1].mem.index: reg = edi
			operands[1].mem.disp: 0x6789
		operands[1].size: 4
		operands[1].access: read

0x1021:	lea		eax, [edi + 0x6789]
bytes:	0x8d 0x87 0x89 0x67 0x00 0x00
	size: 6
	instructions groups: not64bitmode
	opcode: 0x8d
	rex: 0x0
	addr_size: 4
	modrm: 0x87
	disp: 0x6789
	eflags:
	op_count: 2
		operands[0].type: reg = eax
		operands[0].size: 4
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.base: reg = edi
			operands[1].mem.disp: 0x6789
		operands[1].size: 4
		operands[1].access: read

0x1027:	mov		ah, 0xc6
bytes:	0xb4 0xc6
	size: 2
	opcode: 0xb4
	rex: 0x0
	addr_size: 4
	modrm: 0x0
	disp: 0x0
	eflags:
	op_count: 2
		operands[0].type: reg = ah
		operands[0].size: 1
		operands[0].access: write
		operands[1].type: imm = 0xc6
		operands[1].size: 1

0x1029:

****************
Platform: X86 64 (Intel syntax)
Code: 0x55 0x48 0x8b 0x05 0xb8 0x13 0x00 0x00 0x8f 0xe8 0x60 0xcd 0xe2 0x07
Disasm:
0x1000:	push		rbp
bytes:	0x55
	size: 1
	registers read: rsp
	registers modified: rsp
	instructions groups: mode64
	opcode: 0x55
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	eflags:
	op_count: 1
		operands[0].type: reg = rbp
		operands[0].size: 8
		operands[0].access: read

0x1001:	mov		rax, qword ptr [rip + 0x13b8]
bytes:	0x48 0x8b 0x05 0xb8 0x13 0x00 0x00
	size: 7
	opcode: 0x8b
	rex: 0x48
	addr_size: 8
	modrm: 0x5
	disp: 0x13b8
	eflags:
	op_count: 2
		operands[0].type: reg = rax
		operands[0].size: 8
		operands[0].access: write
		operands[1].type: mem
			operands[1].mem.base: reg = rip
			operands[1].mem.disp: 0x13b8
		operands[1].size: 8
		operands[1].access: read

0x1008:	vpcomtruew		xmm4, xmm3, xmm2
bytes:	0x8f 0xe8 0x60 0xcd 0xe2 0x07
	size: 6
	instructions groups: xop
	opcode: 0x8f 0xe8 0x60
	rex: 0x40
	addr_size: 8
	modrm: 0xe2
	disp: 0x0
	sse_cc: 0
	eflags:
	op_count: 3
		operands[0].type: reg = xmm4
		operands[0].size: 16
		operands[0].access: write
		operands[1].type: reg = xmm3
		operands[1].size: 16
		operands[1].access: read
		operands[2].type: reg = xmm2
		operands[2].size: 16
		operands[2].access: read

0x100e: