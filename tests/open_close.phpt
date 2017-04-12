--TEST--
Capstone Test
--INI--
--FILE--
<?php
$ok = cs_support(CS_ARCH_ALL);
printf("support:%d\n", $ok);

$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);

$ok = cs_option($handle, CS_OPT_DETAIL, CS_OPT_ON);
printf("option:%d\n", $ok);

$ok = cs_close($handle);
printf("close:%d\n", $ok);
--EXPECTF--
support:1
resource(%d) of type (Capstone)
option:1
close:1
