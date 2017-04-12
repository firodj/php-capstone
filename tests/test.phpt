--TEST--
Capstone Test
--INI--
--FILE--
<?php
$X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
$X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
$X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00";

$ARM_CODE     = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3";
$ARM_CODE2    = "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3";
$ARMV8        = "\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5";
$THUMB_MCLASS = "\xef\xf3\x02\x80";
$THUMB_CODE   = "\x70\x47\xeb\x46\x83\xb0\xc9\x68";
$THUMB_CODE2  = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0";

$platforms = [
  // X86
  [
    CS_ARCH_X86,
    CS_MODE_16,
    $X86_CODE16,
    "X86 16bit (Intel syntax)"
  ],
  [
    CS_ARCH_X86,
    CS_MODE_32,
    $X86_CODE32,
    "X86 32bit (ATT syntax)",
    CS_OPT_SYNTAX,
    CS_OPT_SYNTAX_ATT,
  ],
  [
    CS_ARCH_X86,
    CS_MODE_32,
    $X86_CODE32,
    "X86 32 (Intel syntax)"
  ],
  [
    CS_ARCH_X86,
    CS_MODE_64,
    $X86_CODE64,
    "X86 64 (Intel syntax)"
  ],

  // ARM
  [ 
    CS_ARCH_ARM,
    CS_MODE_ARM,
    $ARM_CODE,
    "ARM"
  ],
  [
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    $THUMB_CODE2,
    "THUMB-2"
  ],
  [ 
    CS_ARCH_ARM,
    CS_MODE_ARM,
    $ARM_CODE2,
    "ARM: Cortex-A15 + NEON"
  ],
  [
    CS_ARCH_ARM,
    CS_MODE_THUMB,
    $THUMB_CODE,
    "THUMB"
  ],
  [
    CS_ARCH_ARM,
    (CS_MODE_THUMB + CS_MODE_MCLASS),
    $THUMB_MCLASS,
    "Thumb-MClass"
  ],
  [
    CS_ARCH_ARM,
    (CS_MODE_ARM + CS_MODE_V8),
    $ARMV8,
    "Arm-V8"
  ],

];

foreach($platforms as $platform) {
  printf("****************\n");
  printf("Platform: %s\n", $platform[3]);
  $handle = cs_open($platform[0], $platform[1]);
  if (!$handle) continue;

  if (isset($platform[4])) {
    cs_option($handle, $platform[4], $platform[5]);
  }

  printf("Code: %s\n", implode(" ", array_map(function($x) {
    return sprintf("0x%02x", $x);
  }, unpack('C*', $platform[2])
  ))
  );

  printf("Disasm:\n");
  $insn = cs_disasm($handle, $platform[2], 0x1000);

  foreach ($insn as $inst) {
      printf("0x%x:\t%s\t\t%s\n",
          $inst->address, $inst->mnemonic, $inst->op_str);
  }

  printf("0x%x:\n", $inst->address + count($inst->bytes));
  printf("\n");

  cs_close($handle);
}
--EXPECT--
****************
Platform: X86 16bit (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	lea		cx, word ptr [si + 0x32]
0x1003:	or		byte ptr [bx + di], al
0x1005:	fadd		dword ptr [bx + di + 0x34c6]
0x1009:	adc		al, byte ptr [bx + si]
0x100b:

****************
Platform: X86 32bit (ATT syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	leal		8(%edx, %esi), %ecx
0x1004:	addl		%ebx, %eax
0x1006:	addl		$0x1234, %esi
0x100c:

****************
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	lea		ecx, dword ptr [edx + esi + 8]
0x1004:	add		eax, ebx
0x1006:	add		esi, 0x1234
0x100c:

****************
Platform: X86 64 (Intel syntax)
Code: 0x55 0x48 0x8b 0x05 0xb8 0x13 0x00 0x00
Disasm:
0x1000:	push		rbp
0x1001:	mov		rax, qword ptr [rip + 0x13b8]
0x1008:

****************
Platform: ARM
Code: 0xed 0xff 0xff 0xeb 0x04 0xe0 0x2d 0xe5 0x00 0x00 0x00 0x00 0xe0 0x83 0x22 0xe5 0xf1 0x02 0x03 0x0e 0x00 0x00 0xa0 0xe3 0x02 0x30 0xc1 0xe7 0x00 0x00 0x53 0xe3
Disasm:
0x1000:	bl		#0xfbc
0x1004:	str		lr, [sp, #-4]!
0x1008:	andeq		r0, r0, r0
0x100c:	str		r8, [r2, #-0x3e0]!
0x1010:	mcreq		p2, #0, r0, c3, c1, #7
0x1014:	mov		r0, #0
0x1018:	strb		r3, [r1, r2]
0x101c:	cmp		r3, #0
0x1020:

****************
Platform: THUMB-2
Code: 0x4f 0xf0 0x00 0x01 0xbd 0xe8 0x00 0x88 0xd1 0xe8 0x00 0xf0
Disasm:
0x1000:	mov.w		r1, #0
0x1004:	pop.w		{fp, pc}
0x1008:	tbb		[r1, r0]
0x100c:

****************
Platform: ARM: Cortex-A15 + NEON
Code: 0x10 0xf1 0x10 0xe7 0x11 0xf2 0x31 0xe7 0xdc 0xa1 0x2e 0xf3 0xe8 0x4e 0x62 0xf3
Disasm:
0x1000:	sdiv		r0, r0, r1
0x1004:	udiv		r1, r1, r2
0x1008:	vbit		q5, q15, q6
0x100c:	vcgt.f32		q10, q9, q12
0x1010:

****************
Platform: THUMB
Code: 0x70 0x47 0xeb 0x46 0x83 0xb0 0xc9 0x68
Disasm:
0x1000:	bx		lr
0x1002:	mov		fp, sp
0x1004:	sub		sp, #0xc
0x1006:	ldr		r1, [r1, #0xc]
0x1008:

****************
Platform: Thumb-MClass
Code: 0xef 0xf3 0x02 0x80
Disasm:
0x1000:	mrs		r0, eapsr
0x1004:

****************
Platform: Arm-V8
Code: 0xe0 0x3b 0xb2 0xee 0x42 0x00 0x01 0xe1 0x51 0xf0 0x7f 0xf5
Disasm:
0x1000:	vcvtt.f64.f16		d3, s1
0x1004:	crc32b		r0, r1, r2
0x1008:	dmb		oshld
0x100c:


