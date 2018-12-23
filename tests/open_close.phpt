--TEST--
Capstone Test
--INI--
--FILE--
<?php
printf("version:%s\n", cs_version());
$ok = cs_support(CS_ARCH_X86);
printf("support x86:%d\n", $ok);

$handle = cs_open(CS_ARCH_X86, CS_MODE_64);
var_dump($handle);

$ok = cs_option($handle, CS_OPT_DETAIL, CS_OPT_ON);
printf("option:%d\n", $ok);

$ok = cs_close($handle);
printf("close:%d\n", $ok);
--EXPECTF--
version:4.1.0
support x86:1
resource(%d) of type (Capstone)
option:1
close:1
