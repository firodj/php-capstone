--TEST--
Capstone Test
--INI--
--FILE--
<?php
$CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00";

$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);

$insn = cs_disasm($handle, $CODE, 0x1000);
var_dump($insn);
cs_close($handle);
--EXPECTF--
resource(%d) of type (Capstone)
array(2) {
  [0]=>
  object(stdClass)#1 (3) {
    ["address"]=>
    int(4096)
    ["mnemonic"]=>
    string(4) "push"
    ["op_str"]=>
    string(3) "rbp"
  }
  [1]=>
  object(stdClass)#2 (3) {
    ["address"]=>
    int(4097)
    ["mnemonic"]=>
    string(3) "mov"
    ["op_str"]=>
    string(29) "rax, qword ptr [rip + 0x13b8]"
  }
}
