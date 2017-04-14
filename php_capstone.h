#ifndef _PHP_CAPSTONE_H
#define _PHP_CAPSTONE_H

#include "php.h"
#include "zend_smart_str.h"

#include <capstone/capstone.h>

#define _STR_HELPER(x) #x
#define _STR(x) _STR_HELPER(x)

#define PHP_CAPSTONE_VERSION _STR(CS_VERSION_MAJOR) "." _STR(CS_VERSION_MINOR) "." _STR(CS_VERSION_EXTRA)
#define PHP_CAPSTONE_EXTNAME "capstone"

extern int le_capstone;
#define le_capstone_name "Capstone"

void _php_capstone_close(zend_resource*);
#include "const.inc"

PHP_MINIT_FUNCTION(capstone);
PHP_MSHUTDOWN_FUNCTION(capstone);
PHP_MINFO_FUNCTION(capstone);

PHP_FUNCTION(cs_open);
PHP_FUNCTION(cs_close);
PHP_FUNCTION(cs_disasm);
PHP_FUNCTION(cs_support);
PHP_FUNCTION(cs_option);
PHP_FUNCTION(cs_version);

typedef struct {
    csh handle;
    cs_arch arch;
    cs_mode mode;
    zend_bool opt_detail;
    zend_bool opt_skipdata;
} php_capstone;

#endif
