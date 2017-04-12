#include "php_capstone.h"

#define REGISTER_CAPSTONE_CONSTANT(__c) REGISTER_LONG_CONSTANT(#__c, __c, CONST_CS | CONST_PERSISTENT)

void php_capstone_register_constants(int module_number)
{
// {{{ cs_arch
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_ARM);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_ARM64);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_MIPS);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_X86);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_PPC);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_SPARC);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_SYSZ);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_XCORE);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_MAX);
REGISTER_CAPSTONE_CONSTANT(CS_ARCH_ALL);
// }}} cs_arch

// {{{ cs_mode
REGISTER_CAPSTONE_CONSTANT(CS_MODE_LITTLE_ENDIAN);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_ARM);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_16);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_32);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_64);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_THUMB);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MCLASS);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_V8);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MICRO);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MIPS3);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MIPS32R6);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MIPSGP64);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_V9);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_BIG_ENDIAN);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MIPS32);
REGISTER_CAPSTONE_CONSTANT(CS_MODE_MIPS64);
// }}} cs_mode

// {{{ cs_opt_type
REGISTER_CAPSTONE_CONSTANT(CS_OPT_INVALID);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SYNTAX);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_DETAIL);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_MODE);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_MEM);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SKIPDATA);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SKIPDATA_SETUP);
// }}} cs_opt_type

// {{{ cs_opt_value
REGISTER_CAPSTONE_CONSTANT(CS_OPT_OFF);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_ON);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SYNTAX_DEFAULT);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SYNTAX_INTEL);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SYNTAX_ATT);
REGISTER_CAPSTONE_CONSTANT(CS_OPT_SYNTAX_NOREGNAME);
// }}} cs_opt_value

// {{{ cs_op_type
REGISTER_CAPSTONE_CONSTANT(CS_OP_INVALID);
REGISTER_CAPSTONE_CONSTANT(CS_OP_REG);
REGISTER_CAPSTONE_CONSTANT(CS_OP_IMM);
REGISTER_CAPSTONE_CONSTANT(CS_OP_MEM);
REGISTER_CAPSTONE_CONSTANT(CS_OP_FP);
// }}} cs_op_type

// {{{ cs_group_type
REGISTER_CAPSTONE_CONSTANT(CS_GRP_INVALID);
REGISTER_CAPSTONE_CONSTANT(CS_GRP_JUMP);
REGISTER_CAPSTONE_CONSTANT(CS_GRP_CALL);
REGISTER_CAPSTONE_CONSTANT(CS_GRP_RET);
REGISTER_CAPSTONE_CONSTANT(CS_GRP_INT);
REGISTER_CAPSTONE_CONSTANT(CS_GRP_IRET);
// }}} cs_group_type

// {{{ cs_err
REGISTER_CAPSTONE_CONSTANT(CS_ERR_OK);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_MEM);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_ARCH);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_HANDLE);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_CSH);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_MODE);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_OPTION);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_DETAIL);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_MEMSETUP);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_VERSION);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_DIET);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_SKIPDATA);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_X86_ATT);
REGISTER_CAPSTONE_CONSTANT(CS_ERR_X86_INTEL);
// }}} cs_err

}

const char *php_capstone_x86_reg_name(x86_reg id) {
switch (id) {
case X86_REG_AH: return "AH"; break;
case X86_REG_AL: return "AL"; break;
case X86_REG_AX: return "AX"; break;
case X86_REG_BH: return "BH"; break;
case X86_REG_BL: return "BL"; break;
case X86_REG_BP: return "BP"; break;
case X86_REG_BPL: return "BPL"; break;
case X86_REG_BX: return "BX"; break;
case X86_REG_CH: return "CH"; break;
case X86_REG_CL: return "CL"; break;
case X86_REG_CS: return "CS"; break;
case X86_REG_CX: return "CX"; break;
case X86_REG_DH: return "DH"; break;
case X86_REG_DI: return "DI"; break;
case X86_REG_DIL: return "DIL"; break;
case X86_REG_DL: return "DL"; break;
case X86_REG_DS: return "DS"; break;
case X86_REG_DX: return "DX"; break;
case X86_REG_EAX: return "EAX"; break;
case X86_REG_EBP: return "EBP"; break;
case X86_REG_EBX: return "EBX"; break;
case X86_REG_ECX: return "ECX"; break;
case X86_REG_EDI: return "EDI"; break;
case X86_REG_EDX: return "EDX"; break;
case X86_REG_EFLAGS: return "EFLAGS"; break;
case X86_REG_EIP: return "EIP"; break;
case X86_REG_EIZ: return "EIZ"; break;
case X86_REG_ES: return "ES"; break;
case X86_REG_ESI: return "ESI"; break;
case X86_REG_ESP: return "ESP"; break;
case X86_REG_FPSW: return "FPSW"; break;
case X86_REG_FS: return "FS"; break;
case X86_REG_GS: return "GS"; break;
case X86_REG_IP: return "IP"; break;
case X86_REG_RAX: return "RAX"; break;
case X86_REG_RBP: return "RBP"; break;
case X86_REG_RBX: return "RBX"; break;
case X86_REG_RCX: return "RCX"; break;
case X86_REG_RDI: return "RDI"; break;
case X86_REG_RDX: return "RDX"; break;
case X86_REG_RIP: return "RIP"; break;
case X86_REG_RIZ: return "RIZ"; break;
case X86_REG_RSI: return "RSI"; break;
case X86_REG_RSP: return "RSP"; break;
case X86_REG_SI: return "SI"; break;
case X86_REG_SIL: return "SIL"; break;
case X86_REG_SP: return "SP"; break;
case X86_REG_SPL: return "SPL"; break;
case X86_REG_SS: return "SS"; break;
case X86_REG_CR0: return "CR0"; break;
case X86_REG_CR1: return "CR1"; break;
case X86_REG_CR2: return "CR2"; break;
case X86_REG_CR3: return "CR3"; break;
case X86_REG_CR4: return "CR4"; break;
case X86_REG_CR5: return "CR5"; break;
case X86_REG_CR6: return "CR6"; break;
case X86_REG_CR7: return "CR7"; break;
case X86_REG_CR8: return "CR8"; break;
case X86_REG_CR9: return "CR9"; break;
case X86_REG_CR10: return "CR10"; break;
case X86_REG_CR11: return "CR11"; break;
case X86_REG_CR12: return "CR12"; break;
case X86_REG_CR13: return "CR13"; break;
case X86_REG_CR14: return "CR14"; break;
case X86_REG_CR15: return "CR15"; break;
case X86_REG_DR0: return "DR0"; break;
case X86_REG_DR1: return "DR1"; break;
case X86_REG_DR2: return "DR2"; break;
case X86_REG_DR3: return "DR3"; break;
case X86_REG_DR4: return "DR4"; break;
case X86_REG_DR5: return "DR5"; break;
case X86_REG_DR6: return "DR6"; break;
case X86_REG_DR7: return "DR7"; break;
case X86_REG_FP0: return "FP0"; break;
case X86_REG_FP1: return "FP1"; break;
case X86_REG_FP2: return "FP2"; break;
case X86_REG_FP3: return "FP3"; break;
case X86_REG_FP4: return "FP4"; break;
case X86_REG_FP5: return "FP5"; break;
case X86_REG_FP6: return "FP6"; break;
case X86_REG_FP7: return "FP7"; break;
case X86_REG_K0: return "K0"; break;
case X86_REG_K1: return "K1"; break;
case X86_REG_K2: return "K2"; break;
case X86_REG_K3: return "K3"; break;
case X86_REG_K4: return "K4"; break;
case X86_REG_K5: return "K5"; break;
case X86_REG_K6: return "K6"; break;
case X86_REG_K7: return "K7"; break;
case X86_REG_MM0: return "MM0"; break;
case X86_REG_MM1: return "MM1"; break;
case X86_REG_MM2: return "MM2"; break;
case X86_REG_MM3: return "MM3"; break;
case X86_REG_MM4: return "MM4"; break;
case X86_REG_MM5: return "MM5"; break;
case X86_REG_MM6: return "MM6"; break;
case X86_REG_MM7: return "MM7"; break;
case X86_REG_R8: return "R8"; break;
case X86_REG_R9: return "R9"; break;
case X86_REG_R10: return "R10"; break;
case X86_REG_R11: return "R11"; break;
case X86_REG_R12: return "R12"; break;
case X86_REG_R13: return "R13"; break;
case X86_REG_R14: return "R14"; break;
case X86_REG_R15: return "R15"; break;
case X86_REG_ST0: return "ST0"; break;
case X86_REG_ST1: return "ST1"; break;
case X86_REG_ST2: return "ST2"; break;
case X86_REG_ST3: return "ST3"; break;
case X86_REG_ST4: return "ST4"; break;
case X86_REG_ST5: return "ST5"; break;
case X86_REG_ST6: return "ST6"; break;
case X86_REG_ST7: return "ST7"; break;
case X86_REG_XMM0: return "XMM0"; break;
case X86_REG_XMM1: return "XMM1"; break;
case X86_REG_XMM2: return "XMM2"; break;
case X86_REG_XMM3: return "XMM3"; break;
case X86_REG_XMM4: return "XMM4"; break;
case X86_REG_XMM5: return "XMM5"; break;
case X86_REG_XMM6: return "XMM6"; break;
case X86_REG_XMM7: return "XMM7"; break;
case X86_REG_XMM8: return "XMM8"; break;
case X86_REG_XMM9: return "XMM9"; break;
case X86_REG_XMM10: return "XMM10"; break;
case X86_REG_XMM11: return "XMM11"; break;
case X86_REG_XMM12: return "XMM12"; break;
case X86_REG_XMM13: return "XMM13"; break;
case X86_REG_XMM14: return "XMM14"; break;
case X86_REG_XMM15: return "XMM15"; break;
case X86_REG_XMM16: return "XMM16"; break;
case X86_REG_XMM17: return "XMM17"; break;
case X86_REG_XMM18: return "XMM18"; break;
case X86_REG_XMM19: return "XMM19"; break;
case X86_REG_XMM20: return "XMM20"; break;
case X86_REG_XMM21: return "XMM21"; break;
case X86_REG_XMM22: return "XMM22"; break;
case X86_REG_XMM23: return "XMM23"; break;
case X86_REG_XMM24: return "XMM24"; break;
case X86_REG_XMM25: return "XMM25"; break;
case X86_REG_XMM26: return "XMM26"; break;
case X86_REG_XMM27: return "XMM27"; break;
case X86_REG_XMM28: return "XMM28"; break;
case X86_REG_XMM29: return "XMM29"; break;
case X86_REG_XMM30: return "XMM30"; break;
case X86_REG_XMM31: return "XMM31"; break;
case X86_REG_YMM0: return "YMM0"; break;
case X86_REG_YMM1: return "YMM1"; break;
case X86_REG_YMM2: return "YMM2"; break;
case X86_REG_YMM3: return "YMM3"; break;
case X86_REG_YMM4: return "YMM4"; break;
case X86_REG_YMM5: return "YMM5"; break;
case X86_REG_YMM6: return "YMM6"; break;
case X86_REG_YMM7: return "YMM7"; break;
case X86_REG_YMM8: return "YMM8"; break;
case X86_REG_YMM9: return "YMM9"; break;
case X86_REG_YMM10: return "YMM10"; break;
case X86_REG_YMM11: return "YMM11"; break;
case X86_REG_YMM12: return "YMM12"; break;
case X86_REG_YMM13: return "YMM13"; break;
case X86_REG_YMM14: return "YMM14"; break;
case X86_REG_YMM15: return "YMM15"; break;
case X86_REG_YMM16: return "YMM16"; break;
case X86_REG_YMM17: return "YMM17"; break;
case X86_REG_YMM18: return "YMM18"; break;
case X86_REG_YMM19: return "YMM19"; break;
case X86_REG_YMM20: return "YMM20"; break;
case X86_REG_YMM21: return "YMM21"; break;
case X86_REG_YMM22: return "YMM22"; break;
case X86_REG_YMM23: return "YMM23"; break;
case X86_REG_YMM24: return "YMM24"; break;
case X86_REG_YMM25: return "YMM25"; break;
case X86_REG_YMM26: return "YMM26"; break;
case X86_REG_YMM27: return "YMM27"; break;
case X86_REG_YMM28: return "YMM28"; break;
case X86_REG_YMM29: return "YMM29"; break;
case X86_REG_YMM30: return "YMM30"; break;
case X86_REG_YMM31: return "YMM31"; break;
case X86_REG_ZMM0: return "ZMM0"; break;
case X86_REG_ZMM1: return "ZMM1"; break;
case X86_REG_ZMM2: return "ZMM2"; break;
case X86_REG_ZMM3: return "ZMM3"; break;
case X86_REG_ZMM4: return "ZMM4"; break;
case X86_REG_ZMM5: return "ZMM5"; break;
case X86_REG_ZMM6: return "ZMM6"; break;
case X86_REG_ZMM7: return "ZMM7"; break;
case X86_REG_ZMM8: return "ZMM8"; break;
case X86_REG_ZMM9: return "ZMM9"; break;
case X86_REG_ZMM10: return "ZMM10"; break;
case X86_REG_ZMM11: return "ZMM11"; break;
case X86_REG_ZMM12: return "ZMM12"; break;
case X86_REG_ZMM13: return "ZMM13"; break;
case X86_REG_ZMM14: return "ZMM14"; break;
case X86_REG_ZMM15: return "ZMM15"; break;
case X86_REG_ZMM16: return "ZMM16"; break;
case X86_REG_ZMM17: return "ZMM17"; break;
case X86_REG_ZMM18: return "ZMM18"; break;
case X86_REG_ZMM19: return "ZMM19"; break;
case X86_REG_ZMM20: return "ZMM20"; break;
case X86_REG_ZMM21: return "ZMM21"; break;
case X86_REG_ZMM22: return "ZMM22"; break;
case X86_REG_ZMM23: return "ZMM23"; break;
case X86_REG_ZMM24: return "ZMM24"; break;
case X86_REG_ZMM25: return "ZMM25"; break;
case X86_REG_ZMM26: return "ZMM26"; break;
case X86_REG_ZMM27: return "ZMM27"; break;
case X86_REG_ZMM28: return "ZMM28"; break;
case X86_REG_ZMM29: return "ZMM29"; break;
case X86_REG_ZMM30: return "ZMM30"; break;
case X86_REG_ZMM31: return "ZMM31"; break;
case X86_REG_R8B: return "R8B"; break;
case X86_REG_R9B: return "R9B"; break;
case X86_REG_R10B: return "R10B"; break;
case X86_REG_R11B: return "R11B"; break;
case X86_REG_R12B: return "R12B"; break;
case X86_REG_R13B: return "R13B"; break;
case X86_REG_R14B: return "R14B"; break;
case X86_REG_R15B: return "R15B"; break;
case X86_REG_R8D: return "R8D"; break;
case X86_REG_R9D: return "R9D"; break;
case X86_REG_R10D: return "R10D"; break;
case X86_REG_R11D: return "R11D"; break;
case X86_REG_R12D: return "R12D"; break;
case X86_REG_R13D: return "R13D"; break;
case X86_REG_R14D: return "R14D"; break;
case X86_REG_R15D: return "R15D"; break;
case X86_REG_R8W: return "R8W"; break;
case X86_REG_R9W: return "R9W"; break;
case X86_REG_R10W: return "R10W"; break;
case X86_REG_R11W: return "R11W"; break;
case X86_REG_R12W: return "R12W"; break;
case X86_REG_R13W: return "R13W"; break;
case X86_REG_R14W: return "R14W"; break;
case X86_REG_R15W: return "R15W"; break;
case X86_REG_ENDING: return "ENDING"; break;
default: break;
} // switch
return NULL;
} // x86_reg

const char *php_capstone_x86_op_type_name(x86_op_type id) {
switch (id) {
case X86_OP_REG: return "REG"; break;
case X86_OP_IMM: return "IMM"; break;
case X86_OP_MEM: return "MEM"; break;
case X86_OP_FP: return "FP"; break;
default: break;
} // switch
return NULL;
} // x86_op_type

const char *php_capstone_x86_avx_bcast_name(x86_avx_bcast id) {
switch (id) {
case X86_AVX_BCAST_2: return "2"; break;
case X86_AVX_BCAST_4: return "4"; break;
case X86_AVX_BCAST_8: return "8"; break;
case X86_AVX_BCAST_16: return "16"; break;
default: break;
} // switch
return NULL;
} // x86_avx_bcast

const char *php_capstone_x86_sse_cc_name(x86_sse_cc id) {
switch (id) {
case X86_SSE_CC_EQ: return "EQ"; break;
case X86_SSE_CC_LT: return "LT"; break;
case X86_SSE_CC_LE: return "LE"; break;
case X86_SSE_CC_UNORD: return "UNORD"; break;
case X86_SSE_CC_NEQ: return "NEQ"; break;
case X86_SSE_CC_NLT: return "NLT"; break;
case X86_SSE_CC_NLE: return "NLE"; break;
case X86_SSE_CC_ORD: return "ORD"; break;
case X86_SSE_CC_EQ_UQ: return "EQ_UQ"; break;
case X86_SSE_CC_NGE: return "NGE"; break;
case X86_SSE_CC_NGT: return "NGT"; break;
case X86_SSE_CC_FALSE: return "FALSE"; break;
case X86_SSE_CC_NEQ_OQ: return "NEQ_OQ"; break;
case X86_SSE_CC_GE: return "GE"; break;
case X86_SSE_CC_GT: return "GT"; break;
case X86_SSE_CC_TRUE: return "TRUE"; break;
default: break;
} // switch
return NULL;
} // x86_sse_cc

const char *php_capstone_x86_avx_cc_name(x86_avx_cc id) {
switch (id) {
case X86_AVX_CC_EQ: return "EQ"; break;
case X86_AVX_CC_LT: return "LT"; break;
case X86_AVX_CC_LE: return "LE"; break;
case X86_AVX_CC_UNORD: return "UNORD"; break;
case X86_AVX_CC_NEQ: return "NEQ"; break;
case X86_AVX_CC_NLT: return "NLT"; break;
case X86_AVX_CC_NLE: return "NLE"; break;
case X86_AVX_CC_ORD: return "ORD"; break;
case X86_AVX_CC_EQ_UQ: return "EQ_UQ"; break;
case X86_AVX_CC_NGE: return "NGE"; break;
case X86_AVX_CC_NGT: return "NGT"; break;
case X86_AVX_CC_FALSE: return "FALSE"; break;
case X86_AVX_CC_NEQ_OQ: return "NEQ_OQ"; break;
case X86_AVX_CC_GE: return "GE"; break;
case X86_AVX_CC_GT: return "GT"; break;
case X86_AVX_CC_TRUE: return "TRUE"; break;
case X86_AVX_CC_EQ_OS: return "EQ_OS"; break;
case X86_AVX_CC_LT_OQ: return "LT_OQ"; break;
case X86_AVX_CC_LE_OQ: return "LE_OQ"; break;
case X86_AVX_CC_UNORD_S: return "UNORD_S"; break;
case X86_AVX_CC_NEQ_US: return "NEQ_US"; break;
case X86_AVX_CC_NLT_UQ: return "NLT_UQ"; break;
case X86_AVX_CC_NLE_UQ: return "NLE_UQ"; break;
case X86_AVX_CC_ORD_S: return "ORD_S"; break;
case X86_AVX_CC_EQ_US: return "EQ_US"; break;
case X86_AVX_CC_NGE_UQ: return "NGE_UQ"; break;
case X86_AVX_CC_NGT_UQ: return "NGT_UQ"; break;
case X86_AVX_CC_FALSE_OS: return "FALSE_OS"; break;
case X86_AVX_CC_NEQ_OS: return "NEQ_OS"; break;
case X86_AVX_CC_GE_OQ: return "GE_OQ"; break;
case X86_AVX_CC_GT_OQ: return "GT_OQ"; break;
case X86_AVX_CC_TRUE_US: return "TRUE_US"; break;
default: break;
} // switch
return NULL;
} // x86_avx_cc

const char *php_capstone_x86_avx_rm_name(x86_avx_rm id) {
switch (id) {
case X86_AVX_RM_RN: return "RN"; break;
case X86_AVX_RM_RD: return "RD"; break;
case X86_AVX_RM_RU: return "RU"; break;
case X86_AVX_RM_RZ: return "RZ"; break;
default: break;
} // switch
return NULL;
} // x86_avx_rm

const char *php_capstone_x86_prefix_name(x86_prefix id) {
switch (id) {
case X86_PREFIX_LOCK: return "LOCK"; break;
case X86_PREFIX_REP: return "REP"; break;
case X86_PREFIX_REPNE: return "REPNE"; break;
case X86_PREFIX_CS: return "CS"; break;
case X86_PREFIX_SS: return "SS"; break;
case X86_PREFIX_DS: return "DS"; break;
case X86_PREFIX_ES: return "ES"; break;
case X86_PREFIX_FS: return "FS"; break;
case X86_PREFIX_GS: return "GS"; break;
case X86_PREFIX_OPSIZE: return "OPSIZE"; break;
case X86_PREFIX_ADDRSIZE: return "ADDRSIZE"; break;
default: break;
} // switch
return NULL;
} // x86_prefix

