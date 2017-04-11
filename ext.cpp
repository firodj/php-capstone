#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <sstream>
#include <iostream>

#include "php.h"
#include "php_ini.h"

#include "zend.h"
#include "zend_API.h"
#include "zend_compile.h"
#include "zend_operators.h"
#include "zend_hash.h"
#include "zend_extensions.h"
#include "ext/standard/info.h"

#define PHP_CAPSTONE_VERSION "3.0.0"
#define PHP_CAPSTONE_EXTNAME "capstone"

// xhp_rename_function
PHP_FUNCTION(capstone_test)
{
	RETURN_TRUE;
}

//
// Extension entry
static PHP_MINIT_FUNCTION(capstone) {
	return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(capstone) {
 	return SUCCESS;
}

// phpinfo();
static PHP_MINFO_FUNCTION(capstone) {
	php_info_print_table_start();
	php_info_print_table_end();
}

// Module description
zend_function_entry capstone_functions[] = {
  ZEND_FE(capstone_test, NULL)
  {NULL, NULL, NULL}
};

zend_module_entry capstone_module_entry = {
  STANDARD_MODULE_HEADER,
  PHP_CAPSTONE_EXTNAME,
  capstone_functions,
  PHP_MINIT(capstone),
  PHP_MSHUTDOWN(capstone),
  NULL,
  NULL,
  PHP_MINFO(capstone),
  PHP_CAPSTONE_VERSION,
  STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_CAPSTONE
ZEND_GET_MODULE(capstone)
#endif