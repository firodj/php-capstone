<?php

function collect_enums($filename) {
    $file = fopen(__DIR__.'/capstone/include/'.$filename, 'r');
    $state = 0;
    $name = null;
    $enums = [];
    $results = [];

    while(!feof($file)) {
        $line = fgets($file);

        switch($state) {
        case 0:
            if (preg_match('/^typedef enum (\w+)/', $line, $match)) {
                $name = $match[1];
                $enums = [];
                $state = 1;
            }
            break;
        case 1:
            if (preg_match('/^} (\w+)/', $line, $match)) {
                $state = 0;
                if ($name != $match[1]) {
                    fprintf(STDERR, "WARNING: unmatch open-close enum %s != %s", $name, $match[1]);
                }
                $results[$name] = $enums;
            } else {
                foreach(explode(",", $line) as $word) {
                    if (preg_match('/^\s*(\w+)/', $word, $match)) {
                        $enums[] = $match[1];
                    }
                    if (strpos($word, "//") !== false) break;
                    if (strpos($word, "/*") !== false) break;
                }
            }
        }
    }
    fclose($file);

    return $results;
}

///////////////////////////////////////////////////////////////////////////////
//

$output = fopen(__DIR__.'/const.c', 'w');
fwrite($output, <<<SCRIPT
#include "php_capstone.h"

#define REGISTER_CAPSTONE_CONSTANT(__c) REGISTER_LONG_CONSTANT(#__c, __c, CONST_CS | CONST_PERSISTENT)

void php_capstone_register_constants(int module_number)
{

SCRIPT
);

foreach (collect_enums('capstone.h') as $name=>$enums) {
    fprintf($output, sprintf("// {{{ %s\n", $name));
    foreach($enums as $enum) {
        fprintf($output, "REGISTER_CAPSTONE_CONSTANT(%s);\n", $enum);
    }
    fprintf($output, "// }}} %s\n\n", $name);
}

fwrite($output, <<<SCRIPT
}


SCRIPT
);

///////

foreach (collect_enums('x86.h') as $name=>$enums) {
    // Skip: x86_insn
    if ($name == "x86_insn") continue;

    // Fix: x86_op_type
    $str_len = strlen($name) + 1;
    if ($name == "x86_op_type") $str_len -= 5;

    fprintf($output, sprintf("const char *php_capstone_%s_name(%s id) {\n", $name, $name));
    fprintf($output, "switch (id) {\n");
    foreach($enums as $enum) {
        $str = substr($enum, $str_len);
        
        // Skip: INVALID
        if ($str == 'INVALID') continue;

        fprintf($output, "case %s: return \"%s\"; break;\n", $enum, $str);
    }
    fprintf($output, "default: break;\n} // switch\n");
    fprintf($output, "return NULL;\n} // %s\n\n", $name);
}

fclose($output);
