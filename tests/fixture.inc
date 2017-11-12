<?php

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

  // MIPS

  [
    CS_ARCH_MIPS,
    (CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
    $MIPS_CODE,
    "MIPS-32 (Big-endian)"
  ],
  [
    CS_ARCH_MIPS,
    (CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
    $MIPS_CODE2,
    "MIPS-64-EL (Little-endian)"
  ],
  [
    CS_ARCH_MIPS,
    (CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
    $MIPS_32R6M,
    "MIPS-32R6 | Micro (Big-endian)"
  ],
  [
    CS_ARCH_MIPS,
    (CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
    $MIPS_32R6,
    "MIPS-32R6 (Big-endian)"
  ],


  // OTHER
  [
    CS_ARCH_ARM64,
    CS_MODE_ARM,
    $ARM64_CODE,
    "ARM-64"
  ],
  [
    CS_ARCH_PPC,
    CS_MODE_BIG_ENDIAN,
    $PPC_CODE,
    "PPC-64"
  ],
  [
    CS_ARCH_PPC,
    CS_MODE_BIG_ENDIAN,
    $PPC_CODE,
    "PPC-64, print register with number only",
    CS_OPT_SYNTAX,
    CS_OPT_SYNTAX_NOREGNAME
  ],
  [
    CS_ARCH_SPARC,
    CS_MODE_BIG_ENDIAN,
    $SPARC_CODE,
    "Sparc"
  ],
  [
    CS_ARCH_SPARC,
    (CS_MODE_BIG_ENDIAN + CS_MODE_V9),
    $SPARCV9_CODE,
    "SparcV9"
  ],
  [
    CS_ARCH_SYSZ,
    0,
    $SYSZ_CODE,
    "SystemZ"
  ],
  [
    CS_ARCH_XCORE,
    0,
    $XCORE_CODE,
    "XCore"
  ],

];

function string_hex($bytes) {
    if (is_string($bytes)) {
        $bytes = unpack('C*', $bytes);
    }
    return implode(" ",
        array_map(function($x) {
            return is_int($x) ? sprintf("0x%02x", $x) : $x;
            },
            $bytes
        )
    );
};

function print_ins($ins)
{
    printf("0x%x:\t%s", $ins->address, $ins->mnemonic);
    if ($ins->op_str) printf("\t\t%s", $ins->op_str);
    printf("\n");

    printf("bytes:\t%s\n", string_hex($ins->bytes));
    printf("\tsize: %s\n", count($ins->bytes));

    if (count($ins->detail->regs_read)) {
        printf("\tregisters read: %s\n", implode(" ", $ins->detail->regs_read));
    }
    if (count($ins->detail->regs_write)) {
        printf("\tregisters modified: %s\n", implode(" ", $ins->detail->regs_write));
    }
    if (count($ins->detail->groups)) {
        printf("\tinstructions groups: %s\n",
            implode(" ", $ins->detail->groups));
    }
}

function print_x86_detail($x86)
{
    if ($x86->prefix) {
        printf("\tprefix: %s\n", string_hex($x86->prefix));
    }
    printf("\topcode: %s\n", string_hex($x86->opcode));

    printf("\trex: 0x%x\n", $x86->rex);

    printf("\taddr_size: %u\n", $x86->addr_size);
    printf("\tmodrm: 0x%x\n", $x86->modrm);
    printf("\tdisp: 0x%x\n", $x86->disp);

    if ($x86->sib) {
        printf("\tsib: 0x%x\n", $x86->sib);
        if ($x86->sib_base)
            printf("\t\tsib_base: %s\n", $x86->sib_base);
        if ($x86->sib_index)
            printf("\t\tsib_index: %s\n", $x86->sib_index);
        if ($x86->sib_scale)
            printf("\t\tsib_scale: %d\n", $x86->sib_scale);
    }

    // XOP code condition
    if ($x86->xop_cc) {
        printf("\tsse_cc: %u\n", $x86->xop_cc);
    }

    // SSE code condition
    if ($x86->sse_cc) {
        printf("\tsse_cc: %u\n", $x86->sse_cc);
    }

    // AVX code condition
    if ($x86->avx_cc) {
        printf("\tavx_cc: %u\n", $x86->avx_cc);
    }

    // AVX Suppress All Exception
    if ($x86->avx_sae) {
        printf("\tavx_sae: %u\n", $x86->avx_sae);
    }

    // AVX Rounding Mode
    if ($x86->avx_rm) {
        printf("\tavx_rm: %u\n", $x86->avx_rm);
    }

    printf("\teflags:\n");
    foreach($x86->eflags as $ops => $flags) {
        if ($flags) {
            printf("\t\t%s: %s\n", $ops, implode(' ', $flags));
        }
    }

    printf("\top_count: %u\n", count($x86->operands));
    foreach ($x86->operands as $i => $op) {
        switch($op->type) {
            case 'reg': // X86_OP_REG
                printf("\t\toperands[%u].type: reg = %s\n", $i, $op->reg);
                break;
            case 'imm': // X86_OP_IMM
                printf("\t\toperands[%u].type: imm = 0x%x\n", $i, $op->imm);
                break;
            case 'mem': // X86_OP_MEM
                printf("\t\toperands[%u].type: mem\n", $i);
                if ($op->mem->segment)
                    printf("\t\t\toperands[%u].mem.segment: reg = %s\n", $i, $op->mem->segment);
                if ($op->mem->base)
                    printf("\t\t\toperands[%u].mem.base: reg = %s\n", $i, $op->mem->base);
                if ($op->mem->index)
                    printf("\t\t\toperands[%u].mem.index: reg = %s\n", $i, $op->mem->index);
                if ($op->mem->scale)
                    printf("\t\t\toperands[%u].mem.scale: %u\n", $i, $op->mem->scale);
                if ($op->mem->disp)
                    printf("\t\t\toperands[%u].mem.disp: 0x%x\n", $i, $op->mem->disp);
                break;
            default:
                break;
        }

        // AVX broadcast type
        if ($op->avx_bcast)
            printf("\t\toperands[%u].avx_bcast: %u\n", $i, $op->avx_bcast);

        // AVX zero opmask {z}
        if ($op->avx_zero_opmask)
            printf("\t\toperands[%u].avx_zero_opmask: TRUE\n", $i);

        printf("\t\toperands[%u].size: %u\n", $i, $op->size);

        if ($op->access) {
            printf("\t\toperands[%u].access: %s\n", $i, implode(' | ', $op->access));
        }
    }

}
