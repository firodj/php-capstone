--TEST--
Capstone Test
--INI--
--FILE--
<?php
$CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00";

$ok = cs_support(CS_ARCH_ALL);
var_dump($ok);

$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);

$ok = cs_option($handle, CS_OPT_DETAIL, CS_OPT_ON);
var_dump($ok);

$insn = cs_disasm($handle, $CODE, 0x1000);
var_dump($insn);

$ok = cs_close($handle);
var_dump($ok);
--EXPECTF--
bool(true)
resource(%d) of type (Capstone)
bool(true)
array(2) {
  [0]=>
  object(stdClass)#1 (6) {
    ["id"]=>
    int(580)
    ["address"]=>
    int(4096)
    ["size"]=>
    int(1)
    ["bytes"]=>
    string(1) "%s"
    ["mnemonic"]=>
    string(4) "push"
    ["op_str"]=>
    string(3) "rbp"
  }
  [1]=>
  object(stdClass)#2 (6) {
    ["id"]=>
    int(442)
    ["address"]=>
    int(4097)
    ["size"]=>
    int(7)
    ["bytes"]=>
    string(7) "%s"
    ["mnemonic"]=>
    string(3) "mov"
    ["op_str"]=>
    string(29) "rax, qword ptr [rip + 0x13b8]"
  }
}
bool(true)
