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

require 'fixture.php';

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

    printf("code: %s\n", string_hex($platform[2]));

    printf("disasm:\n");
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
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	lea	cx, word ptr [si + 0x32]
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x8d 0x00 0x00 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x4c
	disp: 0x32
	op_count: 2
		operands[0].type: REG = cx
		operands[0].size: 2
		operands[1].type: MEM
			operands[1].mem.base: REG = si
			operands[1].mem.disp: 0x32
		operands[1].size: 2

0x1003:	or	byte ptr [bx + di], al
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x08 0x00 0x00 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x1
	disp: 0x0
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
		operands[0].size: 1
		operands[1].type: REG = al
		operands[1].size: 1

0x1005:	fadd	dword ptr [bx + di + 0x34c6]
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0xd8 0x00 0x00 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x81
	disp: 0x34c6
	op_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = bx
			operands[0].mem.index: REG = di
			operands[0].mem.disp: 0x34c6
		operands[0].size: 4

0x1009:	adc	al, byte ptr [bx + si]
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x12 0x00 0x00 0x00
	rex: 0x0
	addr_size: 2
	modrm: 0x0
	disp: 0x0
	op_count: 2
		operands[0].type: REG = al
		operands[0].size: 1
		operands[1].type: MEM
			operands[1].mem.base: REG = bx
			operands[1].mem.index: REG = si
		operands[1].size: 1

0x100b:

****************
Platform: X86 32bit (ATT syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	leal	8(%edx, %esi), %ecx
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x8d 0x00 0x00 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	disp: 0x8
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	op_count: 2
		operands[0].type: MEM
			operands[0].mem.base: REG = edx
			operands[0].mem.index: REG = esi
			operands[0].mem.disp: 0x8
		operands[0].size: 4
		operands[1].type: REG = ecx
		operands[1].size: 4

0x1004:	addl	%ebx, %eax
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x01 0x00 0x00 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = ebx
		operands[0].size: 4
		operands[1].type: REG = eax
		operands[1].size: 4

0x1006:	addl	$0x1234, %esi
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x81 0x00 0x00 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: IMM = 0x1234
		operands[0].size: 4
		operands[1].type: REG = esi
		operands[1].size: 4

0x100c:

****************
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	lea	ecx, dword ptr [edx + esi + 8]
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x8d 0x00 0x00 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0x4c
	disp: 0x8
	sib: 0x32
		sib_base: edx
		sib_index: esi
		sib_scale: 1
	op_count: 2
		operands[0].type: REG = ecx
		operands[0].size: 4
		operands[1].type: MEM
			operands[1].mem.base: REG = edx
			operands[1].mem.index: REG = esi
			operands[1].mem.disp: 0x8
		operands[1].size: 4

0x1004:	add	eax, ebx
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x01 0x00 0x00 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0xd8
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = eax
		operands[0].size: 4
		operands[1].type: REG = ebx
		operands[1].size: 4

0x1006:	add	esi, 0x1234
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x81 0x00 0x00 0x00
	rex: 0x0
	addr_size: 4
	modrm: 0xc6
	disp: 0x0
	sib: 0x0
	op_count: 2
		operands[0].type: REG = esi
		operands[0].size: 4
		operands[1].type: IMM = 0x1234
		operands[1].size: 4

0x100c:

****************
Platform: X86 64 (Intel syntax)
Code: 0x55 0x48 0x8b 0x05 0xb8 0x13 0x00 0x00
Disasm:
0x1000:	push	rbp
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x55 0x00 0x00 0x00
	rex: 0x0
	addr_size: 8
	modrm: 0x0
	disp: 0x0
	sib: 0x0
	op_count: 1
		operands[0].type: REG = rbp
		operands[0].size: 8

0x1001:	mov	rax, qword ptr [rip + 0x13b8]
	Prefix: 0x00 0x00 0x00 0x00
	Opcode: 0x8b 0x00 0x00 0x00
	rex: 0x48
	addr_size: 8
	modrm: 0x5
	disp: 0x13b8
	sib: 0x0
	op_count: 2
		operands[0].type: REG = rax
		operands[0].size: 8
		operands[1].type: MEM
			operands[1].mem.base: REG = rip
			operands[1].mem.disp: 0x13b8
		operands[1].size: 8

0x1008:
