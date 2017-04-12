#ifndef _PHP_CAPSTONE_H
#define _PHP_CAPSTONE_H

#include "php.h"
#include "zend_smart_str.h"

#include <capstone.h>

#define PHP_CAPSTONE_VERSION "3.0.0"
#define PHP_CAPSTONE_EXTNAME "capstone"

extern int le_capstone;
#define le_capstone_name "Capstone"

void _php_capstone_close(zend_resource*);
void php_capstone_register_constants(int);
const char *php_capstone_x86_reg_name(x86_reg);
const char *php_capstone_x86_op_type_name(x86_op_type);
const char *php_capstone_x86_avx_bcast_name(x86_avx_bcast);
const char *php_capstone_x86_sse_cc_name(x86_sse_cc);
const char *php_capstone_x86_avx_cc_name(x86_avx_cc);
const char *php_capstone_x86_avx_rm_name(x86_avx_rm);
const char *php_capstone_x86_prefix_name(x86_prefix);


PHP_MINIT_FUNCTION(capstone);
PHP_MSHUTDOWN_FUNCTION(capstone);
PHP_MINFO_FUNCTION(capstone);

PHP_FUNCTION(cs_open);
PHP_FUNCTION(cs_close);
PHP_FUNCTION(cs_disasm);
PHP_FUNCTION(cs_support);
PHP_FUNCTION(cs_option);

typedef struct {
    csh handle;
    cs_arch arch;
    cs_mode mode;
    zend_bool opt_detail;
    zend_bool opt_skipdata;
} php_capstone;

#endif
