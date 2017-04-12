#ifndef _PHP_CAPSTONE_H
#define _PHP_CAPSTONE_H

#include "php.h"
#include "zend_smart_str.h"

#include <capstone.h>

#define PHP_CAPSTONE_VERSION "3.0.0"
#define PHP_CAPSTONE_EXTNAME "capstone"

int le_capstone;
#define le_capstone_name "Capstone"

void _php_capstone_close(zend_resource *rsrc);

PHP_MINIT_FUNCTION(capstone);
PHP_MSHUTDOWN_FUNCTION(capstone);
PHP_MINFO_FUNCTION(capstone);

PHP_FUNCTION(cs_open);
PHP_FUNCTION(cs_close);

typedef struct {
    csh handle;
} php_capstone;

#endif