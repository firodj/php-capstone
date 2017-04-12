--TEST--
Capstone Test
--INI--
--FILE--
<?php
$CODE = "\x55\x48\x8b\x05\xb8\x13\x00\x00";

$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);

$insn = cs_disasm($handle, $CODE, 0x1000);

cs_close($handle);
--EXPECTF--
resource(%d) of type (Capstone)
