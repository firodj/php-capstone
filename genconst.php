<?php

$output = fopen(__DIR__.'/const.c', 'w');
fwrite($output, <<<SCRIPT
#include "php_capstone.h"

#define REGISTER_CAPSTONE_CONSTANT(__c) REGISTER_LONG_CONSTANT(#__c, __c, CONST_CS | CONST_PERSISTENT)

void php_capstone_register_constants(int module_number)
{

SCRIPT
);

$file = fopen(__DIR__.'/capstone/include/capstone.h', 'r');
$state = 0;
$name = null;
while(!feof($file)) {
    $line = fgets($file);

    switch($state) {
    case 0:
        if (preg_match('/^typedef enum (\w+)/', $line, $match)) {
            $name = $match[1];
            $state = 1;
            fprintf($output, sprintf("// {{{ %s\n", $name));
        }
        break;
    case 1:
        if (preg_match('/^} (\w+)/', $line, $match)) {
            fprintf($output, "// }}} %s\n\n", $name);
            $state = 0;
            if ($name != $match[1]) {
                fprintf(STDERR, "WARNING: unmatch open-close enum");
            }
        } else if (preg_match('/^\s+(\w+)/', $line, $match)) {
            $const = $match[1];
            fprintf($output, "REGISTER_CAPSTONE_CONSTANT(%s);\n", $const);
        }
    }
}
fclose($file);
fwrite($output, <<<SCRIPT
}
SCRIPT
);
fclose($output);
