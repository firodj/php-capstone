--TEST--
Capstone Test
--INI--
--FILE--
<?php
$CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00";

$ok = cs_support(CS_ARCH_ALL);
printf("support:%d\n", $ok);

$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);

$ok = cs_option($handle, CS_OPT_DETAIL, CS_OPT_ON);
printf("option:%d\n", $ok);

$insn = cs_disasm($handle, $CODE, 0x1000);
printf("count:%d\n", count($insn));

foreach ($insn as $ins) {
  echo json_encode($ins) . "\n";
}

$ok = cs_close($handle);
printf("close:%d\n", $ok);
--EXPECTF--
support:1
resource(%d) of type (Capstone)
option:1
count:2
{"address":4096,"mnemonic":"push","op_str":"rbp","bytes":[85],"regs_read":["rsp"],"regs_write":["rsp"],"groups":["mode64"],"prefix":[0,0,0,0],"opcode":[85,0,0,0],"rex":0,"addr_size":8,"modrm":0,"sib":0,"disp":0,"sib_index":0,"sib_scale":0,"sib_base":0,"sse_cc":0,"avx_cc":0,"avx_sae":false,"avx_rm":0,"operands":[{"type":"reg","reg":"rbp","size":8,"avx_bcast":0,"avx_zero_opmask":false}]}
{"address":4097,"mnemonic":"mov","op_str":"rax, qword ptr [rip + 0x13b8]","bytes":[72,139,5,184,19,0,0],"regs_read":[],"regs_write":[],"groups":[],"prefix":[0,0,0,0],"opcode":[139,0,0,0],"rex":72,"addr_size":8,"modrm":5,"sib":0,"disp":5048,"sib_index":0,"sib_scale":0,"sib_base":0,"sse_cc":0,"avx_cc":0,"avx_sae":false,"avx_rm":0,"operands":[{"type":"reg","reg":"rax","size":8,"avx_bcast":0,"avx_zero_opmask":false},{"type":"mem","segment":0,"base":"rip","index":0,"scale":1,"disp":5048,"size":8,"avx_bcast":0,"avx_zero_opmask":false}]}
close:1
