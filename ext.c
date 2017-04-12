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

//
// Extension entry
PHP_MINIT_FUNCTION(capstone) {
    le_capstone = zend_register_list_destructors_ex(_php_capstone_close, NULL,
        le_capstone_name, module_number);

    php_capstone_register_constants(module_number);

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

ZEND_BEGIN_ARG_INFO_EX(arginfo_cs_disasm, 0, ZEND_RETURN_VALUE, 2)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, code)
    ZEND_ARG_INFO(0, address)
    ZEND_ARG_INFO(0, count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_cs_option, 0, ZEND_RETURN_VALUE, 3)
    ZEND_ARG_INFO(0, handle)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

// Module description
zend_function_entry capstone_functions[] = {
  ZEND_FE(cs_open, arginfo_cs_open)
  ZEND_FE(cs_close, arginfo_cs_close)
  ZEND_FE(cs_disasm, arginfo_cs_disasm)
  ZEND_FE(cs_support, arginfo_cs_close)
  ZEND_FE(cs_option, arginfo_cs_option)
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
    cs_err err = cs_close(&cs_handle->handle);
    efree(cs_handle);

    if (err != CS_ERR_OK) {
        php_error_docref(NULL, E_WARNING, cs_strerror(err));
    }
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
    cs_err err;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_LONG(arch)
        Z_PARAM_LONG(mode)
    ZEND_PARSE_PARAMETERS_END();

    if ((err = cs_open((cs_arch)arch, (cs_mode)mode, &handle)) != CS_ERR_OK) {
        php_error_docref(NULL, E_WARNING, cs_strerror(err));
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
    RETURN_TRUE;
}

PHP_FUNCTION(cs_disasm)
{
    zval *zid;
    zend_string *code;
    zend_long address = 0;
    zend_long count = 0;
    size_t disasm_count;
    cs_insn *insn;
    php_capstone *cs_handle;

    ZEND_PARSE_PARAMETERS_START(2, 4)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_STR(code)
        Z_PARAM_OPTIONAL
        Z_PARAM_LONG(address)
        Z_PARAM_LONG(count)
    ZEND_PARSE_PARAMETERS_END();

    if ((cs_handle = (php_capstone*)zend_fetch_resource(Z_RES_P(zid), le_capstone_name, le_capstone)) == NULL) {
        RETURN_FALSE;
    }

    array_init(return_value);

    disasm_count = cs_disasm(cs_handle->handle, (const uint8_t*)ZSTR_VAL(code), ZSTR_LEN(code), address, count, &insn);

    if (disasm_count > 0)
    {
        size_t j;
        zval instob;

        for (j = 0; j < disasm_count; j++) {
            object_init(&instob);

            add_property_long(&instob, "id", insn[j].id);
            add_property_long(&instob, "address", insn[j].address);
            add_property_long(&instob, "size", insn[j].size);
            add_property_stringl(&instob, "bytes", (const char*)insn[j].bytes, insn[j].size);
            add_property_string(&instob, "mnemonic", insn[j].mnemonic);
            add_property_string(&instob, "op_str", insn[j].op_str);

            add_next_index_zval(return_value, &instob);
        }

        cs_free(insn, disasm_count);
    }
}

PHP_FUNCTION(cs_support)
{
    zend_long query;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(query)
    ZEND_PARSE_PARAMETERS_END();

    if (cs_support(query)) {
        RETURN_TRUE;
    }

    RETURN_FALSE;
}

PHP_FUNCTION(cs_option)
{
    zval *zid;
    zend_long type;
    zend_long value;
    cs_err err;
    php_capstone *cs_handle;

    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_RESOURCE(zid)
        Z_PARAM_LONG(type)
        Z_PARAM_LONG(value)
    ZEND_PARSE_PARAMETERS_END();

    if ((cs_handle = (php_capstone*)zend_fetch_resource(Z_RES_P(zid), le_capstone_name, le_capstone)) == NULL) {
        RETURN_FALSE;
    }

    if ((err = cs_option(cs_handle->handle, (cs_opt_type)type, value)) != CS_ERR_OK) {
        php_error_docref(NULL, E_WARNING, cs_strerror(err));
        RETURN_FALSE;
    }

    RETURN_TRUE;
}
