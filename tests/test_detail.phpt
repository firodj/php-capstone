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

$MIPS_CODE  = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56";
$MIPS_CODE2 = "\x56\x34\x21\x34\xc2\x17\x01\x00";
$MIPS_32R6M = "\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0";
$MIPS_32R6  = "\xec\x80\x00\x19\x7c\x43\x22\xa0";

$ARM64_CODE   = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9";
$PPC_CODE     = "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21";
$SPARC_CODE   = "\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03";
$SPARCV9_CODE = "\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0";
$SYSZ_CODE    = "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78";
$XCORE_CODE   = "\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10";

require 'fixture.php';

foreach($platforms as $platform) {
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

  foreach ($insn as $inst) {
      printf("0x%x:\t%s\t\t%s\n",
          $inst->address, $inst->mnemonic, $inst->op_str);
    if (count($inst->detail->regs_read)) {
        printf("\tImplicit registers read: %s\n", implode(" ", $inst->detail->regs_read));
    }
    if (count($inst->detail->regs_write)) {
        printf("\tImplicit registers modified: %s\n", implode(" ", $inst->detail->regs_write));
    }
    if (count($inst->detail->groups)) {
        printf("\tThis instruction belongs to groups: %s\n",
            implode(" ", $inst->detail->groups));
    }
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
	Implicit registers modified: flags
0x1005:	fadd		dword ptr [bx + di + 0x34c6]
	Implicit registers modified: fpsw
0x1009:	adc		al, byte ptr [bx + si]
	Implicit registers read: flags
	Implicit registers modified: flags
0x100b:

****************
Platform: X86 32bit (ATT syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	leal		8(%edx, %esi), %ecx
	This instruction belongs to groups: not64bitmode
0x1004:	addl		%ebx, %eax
	Implicit registers modified: eflags
0x1006:	addl		$0x1234, %esi
	Implicit registers modified: eflags
0x100c:

****************
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00
Disasm:
0x1000:	lea		ecx, dword ptr [edx + esi + 8]
	This instruction belongs to groups: not64bitmode
0x1004:	add		eax, ebx
	Implicit registers modified: eflags
0x1006:	add		esi, 0x1234
	Implicit registers modified: eflags
0x100c:

****************
Platform: X86 64 (Intel syntax)
Code: 0x55 0x48 0x8b 0x05 0xb8 0x13 0x00 0x00
Disasm:
0x1000:	push		rbp
	Implicit registers read: rsp
	Implicit registers modified: rsp
	This instruction belongs to groups: mode64
0x1001:	mov		rax, qword ptr [rip + 0x13b8]
0x1008:

****************
Platform: ARM
Code: 0xed 0xff 0xff 0xeb 0x04 0xe0 0x2d 0xe5 0x00 0x00 0x00 0x00 0xe0 0x83 0x22 0xe5 0xf1 0x02 0x03 0x0e 0x00 0x00 0xa0 0xe3 0x02 0x30 0xc1 0xe7 0x00 0x00 0x53 0xe3
Disasm:
0x1000:	bl		#0xfbc
	Implicit registers read: pc
	Implicit registers modified: lr
	This instruction belongs to groups: arm jump
0x1004:	str		lr, [sp, #-4]!
	This instruction belongs to groups: arm
0x1008:	andeq		r0, r0, r0
	This instruction belongs to groups: arm
0x100c:	str		r8, [r2, #-0x3e0]!
	This instruction belongs to groups: arm
0x1010:	mcreq		p2, #0, r0, c3, c1, #7
	This instruction belongs to groups: arm
0x1014:	mov		r0, #0
	This instruction belongs to groups: arm
0x1018:	strb		r3, [r1, r2]
	This instruction belongs to groups: arm
0x101c:	cmp		r3, #0
	Implicit registers modified: cpsr
	This instruction belongs to groups: arm
0x1020:

****************
Platform: THUMB-2
Code: 0x4f 0xf0 0x00 0x01 0xbd 0xe8 0x00 0x88 0xd1 0xe8 0x00 0xf0
Disasm:
0x1000:	mov.w		r1, #0
	This instruction belongs to groups: thumb2
0x1004:	pop.w		{fp, pc}
	This instruction belongs to groups: thumb2
0x1008:	tbb		[r1, r0]
	This instruction belongs to groups: thumb2 jump
0x100c:

****************
Platform: ARM: Cortex-A15 + NEON
Code: 0x10 0xf1 0x10 0xe7 0x11 0xf2 0x31 0xe7 0xdc 0xa1 0x2e 0xf3 0xe8 0x4e 0x62 0xf3
Disasm:
0x1000:	sdiv		r0, r0, r1
	This instruction belongs to groups: arm
0x1004:	udiv		r1, r1, r2
	This instruction belongs to groups: arm
0x1008:	vbit		q5, q15, q6
	This instruction belongs to groups: neon
0x100c:	vcgt.f32		q10, q9, q12
	This instruction belongs to groups: neon
0x1010:

****************
Platform: THUMB
Code: 0x70 0x47 0xeb 0x46 0x83 0xb0 0xc9 0x68
Disasm:
0x1000:	bx		lr
	This instruction belongs to groups: thumb jump
0x1002:	mov		fp, sp
	This instruction belongs to groups: thumb thumb1only
0x1004:	sub		sp, #0xc
	This instruction belongs to groups: thumb thumb1only
0x1006:	ldr		r1, [r1, #0xc]
	This instruction belongs to groups: thumb thumb1only
0x1008:

****************
Platform: Thumb-MClass
Code: 0xef 0xf3 0x02 0x80
Disasm:
0x1000:	mrs		r0, eapsr
	This instruction belongs to groups: thumb mclass
0x1004:

****************
Platform: Arm-V8
Code: 0xe0 0x3b 0xb2 0xee 0x42 0x00 0x01 0xe1 0x51 0xf0 0x7f 0xf5
Disasm:
0x1000:	vcvtt.f64.f16		d3, s1
	This instruction belongs to groups: fparmv8 dpvfp
0x1004:	crc32b		r0, r1, r2
	This instruction belongs to groups: arm v8 crc
0x1008:	dmb		oshld
	This instruction belongs to groups: arm databarrier
0x100c:

****************
Platform: MIPS-32 (Big-endian)
Code: 0x0c 0x10 0x00 0x97 0x00 0x00 0x00 0x00 0x24 0x02 0x00 0x0c 0x8f 0xa2 0x00 0x00 0x34 0x21 0x34 0x56
Disasm:
0x1000:	jal		0x40025c
	Implicit registers modified: ra
	This instruction belongs to groups: stdenc
0x1004:	nop		
	This instruction belongs to groups: stdenc
0x1008:	addiu		$v0, $zero, 0xc
	This instruction belongs to groups: stdenc
0x100c:	lw		$v0, ($sp)
	This instruction belongs to groups: stdenc
0x1010:	ori		$at, $at, 0x3456
	This instruction belongs to groups: stdenc
0x1014:

****************
Platform: MIPS-64-EL (Little-endian)
Code: 0x56 0x34 0x21 0x34 0xc2 0x17 0x01 0x00
Disasm:
0x1000:	ori		$at, $at, 0x3456
	This instruction belongs to groups: stdenc
0x1004:	srl		$v0, $at, 0x1f
	This instruction belongs to groups: stdenc
0x1008:

****************
Platform: MIPS-32R6 | Micro (Big-endian)
Code: 0x00 0x07 0x00 0x07 0x00 0x11 0x93 0x7c 0x01 0x8c 0x8b 0x7c 0x00 0xc7 0x48 0xd0
Disasm:
0x1000:	break		7, 0
	This instruction belongs to groups: micromips
0x1004:	wait		0x11
	This instruction belongs to groups: micromips
0x1008:	syscall		0x18c
	This instruction belongs to groups: micromips
0x100c:	rotrv		$t1, $a2, $a3
	This instruction belongs to groups: micromips
0x1010:

****************
Platform: MIPS-32R6 (Big-endian)
Code: 0xec 0x80 0x00 0x19 0x7c 0x43 0x22 0xa0
Disasm:
0x1000:	addiupc		$a0, 0x64
	This instruction belongs to groups: stdenc mips32r6
0x1004:	align		$a0, $v0, $v1, 2
	This instruction belongs to groups: stdenc mips32r6
0x1008:

****************
Platform: ARM-64
Code: 0x21 0x7c 0x02 0x9b 0x21 0x7c 0x00 0x53 0x00 0x40 0x21 0x4b 0xe1 0x0b 0x40 0xb9
Disasm:
0x1000:	mul		x1, x1, x2
0x1004:	lsr		w1, w1, #0
0x1008:	sub		w0, w0, w1, uxtw
0x100c:	ldr		w1, [sp, #8]
0x1010:

****************
Platform: PPC-64
Code: 0x80 0x20 0x00 0x00 0x80 0x3f 0x00 0x00 0x10 0x43 0x23 0x0e 0xd0 0x44 0x00 0x80 0x4c 0x43 0x22 0x02 0x2d 0x03 0x00 0x80 0x7c 0x43 0x20 0x14 0x7c 0x43 0x20 0x93 0x4f 0x20 0x00 0x21 0x4c 0xc8 0x00 0x21
Disasm:
0x1000:	lwz		r1, 0(0)
0x1004:	lwz		r1, 0(r31)
0x1008:	vpkpx		v2, v3, v4
	This instruction belongs to groups: altivec
0x100c:	stfs		f2, 0x80(r4)
0x1010:	crand		2, 3, 4
0x1014:	cmpwi		cr2, r3, 0x80
0x1018:	addc		r2, r3, r4
	Implicit registers modified: ca
0x101c:	mulhd.		r2, r3, r4
	Implicit registers modified: cr0
0x1020:	bdnzlrl+		
	Implicit registers read: ctr lr rm
	Implicit registers modified: ctr
0x1024:	bgelrl-		cr2
	Implicit registers read: ctr lr rm
	Implicit registers modified: lr ctr
0x1028:

****************
Platform: PPC-64, print register with number only
Code: 0x80 0x20 0x00 0x00 0x80 0x3f 0x00 0x00 0x10 0x43 0x23 0x0e 0xd0 0x44 0x00 0x80 0x4c 0x43 0x22 0x02 0x2d 0x03 0x00 0x80 0x7c 0x43 0x20 0x14 0x7c 0x43 0x20 0x93 0x4f 0x20 0x00 0x21 0x4c 0xc8 0x00 0x21
Disasm:
0x1000:	lwz		1, 0(0)
0x1004:	lwz		1, 0(31)
0x1008:	vpkpx		2, 3, 4
	This instruction belongs to groups: altivec
0x100c:	stfs		2, 0x80(4)
0x1010:	crand		2, 3, 4
0x1014:	cmpwi		2, 3, 0x80
0x1018:	addc		2, 3, 4
	Implicit registers modified: ca
0x101c:	mulhd.		2, 3, 4
	Implicit registers modified: cr0
0x1020:	bdnzlrl+		
	Implicit registers read: ctr lr rm
	Implicit registers modified: ctr
0x1024:	bgelrl-		cr2
	Implicit registers read: ctr lr rm
	Implicit registers modified: lr ctr
0x1028:

****************
Platform: Sparc
Code: 0x80 0xa0 0x40 0x02 0x85 0xc2 0x60 0x08 0x85 0xe8 0x20 0x01 0x81 0xe8 0x00 0x00 0x90 0x10 0x20 0x01 0xd5 0xf6 0x10 0x16 0x21 0x00 0x00 0x0a 0x86 0x00 0x40 0x02 0x01 0x00 0x00 0x00 0x12 0xbf 0xff 0xff 0x10 0xbf 0xff 0xff 0xa0 0x02 0x00 0x09 0x0d 0xbf 0xff 0xff 0xd4 0x20 0x60 0x00 0xd4 0x4e 0x00 0x16 0x2a 0xc2 0x80 0x03
Disasm:
0x1000:	cmp		%g1, %g2
	Implicit registers modified: icc
0x1004:	jmpl		%o1+8, %g2
0x1008:	restore		%g0, 1, %g2
0x100c:	restore		
0x1010:	mov		1, %o0
0x1014:	casx		[%i0], %l6, %o2
	This instruction belongs to groups: 64bit
0x1018:	sethi		0xa, %l0
0x101c:	add		%g1, %g2, %g3
0x1020:	nop		
0x1024:	bne		0x1020
	Implicit registers read: icc
	This instruction belongs to groups: jump
0x1028:	ba		0x1024
	This instruction belongs to groups: jump
0x102c:	add		%o0, %o1, %l0
0x1030:	fbg		0x102c
	Implicit registers read: fcc0
	This instruction belongs to groups: jump
0x1034:	st		%o2, [%g1]
0x1038:	ldsb		[%i0+%l6], %o2
0x103c:	brnz,a,pn		%o2, 0x1048
	This instruction belongs to groups: 64bit jump
0x1040:

****************
Platform: SparcV9
Code: 0x81 0xa8 0x0a 0x24 0x89 0xa0 0x10 0x20 0x89 0xa0 0x1a 0x60 0x89 0xa0 0x00 0xe0
Disasm:
0x1000:	fcmps		%f0, %f4
0x1004:	fstox		%f0, %f4
	This instruction belongs to groups: 64bit
0x1008:	fqtoi		%f0, %f4
	This instruction belongs to groups: hardquad
0x100c:	fnegq		%f0, %f4
	This instruction belongs to groups: v9
0x1010:

****************
Platform: SystemZ
Code: 0xed 0x00 0x00 0x00 0x00 0x1a 0x5a 0x0f 0x1f 0xff 0xc2 0x09 0x80 0x00 0x00 0x00 0x07 0xf7 0xeb 0x2a 0xff 0xff 0x7f 0x57 0xe3 0x01 0xff 0xff 0x7f 0x57 0xeb 0x00 0xf0 0x00 0x00 0x24 0xb2 0x4f 0x00 0x78
Disasm:
0x1000:	adb		%f0, 0
	Implicit registers modified: cc
0x1006:	a		%r0, 0xfff(%r15, %r1)
	Implicit registers modified: cc
0x100a:	afi		%r0, -0x80000000
	Implicit registers modified: cc
0x1010:	br		%r7
	This instruction belongs to groups: jump
0x1012:	xiy		0x7ffff(%r15), 0x2a
	Implicit registers modified: cc
0x1018:	xy		%r0, 0x7ffff(%r1, %r15)
	Implicit registers modified: cc
0x101e:	stmg		%r0, %r0, 0(%r15)
0x1024:	ear		%r7, %a8
0x1028:

****************
Platform: XCore
Code: 0xfe 0x0f 0xfe 0x17 0x13 0x17 0xc6 0xfe 0xec 0x17 0x97 0xf8 0xec 0x4f 0x1f 0xfd 0xec 0x37 0x07 0xf2 0x45 0x5b 0xf9 0xfa 0x02 0x06 0x1b 0x10
Disasm:
0x1000:	get		r11, ed
	Implicit registers modified: r11
0x1002:	ldw		et, sp[4]
	Implicit registers read: sp
0x1004:	setd		res[r3], r4
0x1006:	init		t[r2]:lr, r1
0x100a:	divu		r9, r1, r3
0x100e:	lda16		r9, r3[-r11]
0x1012:	ldw		dp, dp[0x81c5]
0x1016:	lmul		r11, r0, r2, r5, r8, r10
0x101a:	add		r1, r2, r3
0x101c:

