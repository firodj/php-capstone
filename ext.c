#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"

#include "zend.h"
#include "zend_API.h"
#include "zend_compile.h"
#include "zend_operators.h"
#include "zend_hash.h"
#include "zend_extensions.h"
#include "ext/standard/info.h"

#include "php_capstone.h"

int le_capstone;

#define REGISTER_CAPSTONE_CONSTANT(__c) REGISTER_LONG_CONSTANT(#__c, __c, CONST_CS | CONST_PERSISTENT)

//
// Extension entry
PHP_MINIT_FUNCTION(capstone) {
    le_capstone = zend_register_list_destructors_ex(_php_capstone_close, NULL,
        le_capstone_name, module_number);

    REGISTER_CAPSTONE_CONSTANT(CS_ARCH_ARM);
    REGISTER_CAPSTONE_CONSTANT(CS_ARCH_X86);
    REGISTER_CAPSTONE_CONSTANT(CS_MODE_64);

	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(capstone) {
 	return SUCCESS;
}

// phpinfo();
PHP_MINFO_FUNCTION(capstone) {
	php_info_print_table_start();
	php_info_print_table_end();
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_cs_open, 0, ZEND_RETURN_VALUE, 2)
	ZEND_ARG_INFO(0, arch)
	ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_cs_close, 0, ZEND_RETURN_VALUE, 1)
	ZEND_ARG_INFO(0, handle)
ZEND_END_ARG_INFO()

// Module description
zend_function_entry capstone_functions[] = {
  ZEND_FE(cs_open, NULL)
  ZEND_FE(cs_close, NULL)
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

void _php_capstone_close(zend_resource *rsrc)
{
	php_capstone *cs_handle = (php_capstone *) rsrc->ptr;
	cs_close(&cs_handle->handle);
	efree(cs_handle);
}

php_capstone *alloc_capstone_handle()
{
    php_capstone *cs_handle = ecalloc(1, sizeof(php_capstone));
    return cs_handle;
}

PHP_FUNCTION(cs_open)
{
    zend_long arch;
    zend_long mode;
    csh handle;
    php_capstone *cs_handle;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_LONG(arch)
		Z_PARAM_LONG(mode)
	ZEND_PARSE_PARAMETERS_END();

    if (cs_open((cs_arch)arch, (cs_mode)mode, &handle) != CS_ERR_OK) {
        RETURN_NULL();
    }

    cs_handle = alloc_capstone_handle();
    cs_handle->handle = handle;

    RETURN_RES(zend_register_resource(cs_handle, le_capstone));
}

PHP_FUNCTION(cs_close)
{
    zval *zid;
    php_capstone *cs_handle;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_RESOURCE(zid)
	ZEND_PARSE_PARAMETERS_END();

	if ((cs_handle = (php_capstone*)zend_fetch_resource(Z_RES_P(zid), le_capstone_name, le_capstone)) == NULL) {
		RETURN_FALSE;
	}

	zend_list_close(Z_RES_P(zid));
}

