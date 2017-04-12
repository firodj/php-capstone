--TEST--
Capstone Test
--INI--
--FILE--
<?php
$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);
cs_close($handle);
--EXPECTF--
resource(%d) of type (Capstone)
