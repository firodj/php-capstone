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
    php_info_print_table_row(2, "Capstone-Engine Support", "Enabled");
    php_info_print_table_row(2, "Capstone Version", PHP_CAPSTONE_VERSION);
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

void arch_detail_x86(php_capstone *cs_handle, zval *pdetailob, cs_x86 *arch)
{
    int n;
    zval info, archob;
    const char *name;

    object_init(&archob);

    array_init(&info);
    for (n=0; n<4; n++) {
        name = php_capstone_x86_prefix_name(arch->prefix[n]);
        if (name) {
            add_next_index_string(&info, name);
        } else {
            add_next_index_long(&info, arch->prefix[n]);
        }
    }
    add_property_zval(&archob, "prefix", &info);

    array_init(&info);
    for (n=0; n<4; n++) {
        add_next_index_long(&info, arch->opcode[n]);
    }
    add_property_zval(&archob, "opcode", &info);

    add_property_long(&archob, "rex", arch->rex);
    add_property_long(&archob, "addr_size", arch->addr_size);
    add_property_long(&archob, "modrm", arch->modrm);
    add_property_long(&archob, "sib", arch->sib);
    add_property_long(&archob, "disp", arch->disp);

    if ((cs_handle->mode & CS_MODE_16) == 0) {

        name = php_capstone_x86_reg_name(arch->sib_index);
        if (name) {
            add_property_string(&archob, "sib_index", name);
        } else {
            add_property_long(&archob, "sib_index", arch->sib_index);
        }

        add_property_long(&archob, "sib_scale", arch->sib_scale);

        name = php_capstone_x86_reg_name(arch->sib_base);
        if (name) {
            add_property_string(&archob, "sib_base", name);
        } else {
            add_property_long(&archob, "sib_base", arch->sib_base);
        }
    }

    name = php_capstone_x86_sse_cc_name(arch->sse_cc);
    if (name) {
        add_property_string(&archob, "sse_cc", name);
    } else {
        add_property_long(&archob, "sse_cc", arch->sse_cc);
    }

    name = php_capstone_x86_avx_cc_name(arch->avx_cc);
    if (name) {
        add_property_string(&archob, "avx_cc", name);
    } else {
        add_property_long(&archob, "avx_cc", arch->avx_cc);
    }

    add_property_bool(&archob, "avx_sae", arch->avx_sae);

    name = php_capstone_x86_avx_rm_name(arch->avx_rm);
    if (name) {
        add_property_string(&archob, "avx_rm", name);
    } else {
        add_property_long(&archob, "avx_rm", arch->avx_rm);
    }

    array_init(&info);
    for (n=0; n<arch->op_count; n++) {
        cs_x86_op *op = &arch->operands[n];
        zval opob, memob;

        object_init(&opob);

        name = php_capstone_x86_op_type_name(op->type);
        if (name) {
            add_property_string(&opob, "type", name);
        } else {
            add_property_long(&opob, "type", op->type);
        }

        switch (op->type) {
            case X86_OP_REG: 
                name = php_capstone_x86_reg_name(op->reg);
                if (name) {
                    add_property_string(&opob, "reg", name);
                } else {
                    add_property_long(&opob, "reg", op->reg);
                }
                break;
            case X86_OP_IMM:
                add_property_long(&opob, "imm", op->imm);
                break;
            case X86_OP_MEM:
                object_init(&memob);

                name = php_capstone_x86_reg_name(op->mem.segment);
                if (name) {
                    add_property_string(&memob, "segment", name);
                } else {
                    add_property_long(&memob, "segment", op->mem.segment);
                }

                name = php_capstone_x86_reg_name(op->mem.base);
                if (name) {
                    add_property_string(&memob, "base", name);
                } else {
                    add_property_long(&memob, "base", op->mem.base);
                }

                name = php_capstone_x86_reg_name(op->mem.index);
                if (name) {
                    add_property_string(&memob, "index", name);
                } else {
                    add_property_long(&memob, "index", op->mem.index);
                }

                add_property_long(&memob, "scale", op->mem.scale);
                add_property_long(&memob, "disp", op->mem.disp);

                add_property_zval(&opob, "mem", &memob);
                break;
            case X86_OP_FP:
                add_property_double(&opob, "fp", op->fp);
                break;
            default:
                break;
        }

        add_property_long(&opob, "size", op->size);

        name = php_capstone_x86_avx_bcast_name(op->avx_bcast);
        if (name) {
            add_property_string(&opob, "avx_bcast", name);
        } else {
            add_property_long(&opob, "avx_bcast", op->avx_bcast);
        }

        add_property_bool(&opob, "avx_zero_opmask", op->avx_zero_opmask);

        add_next_index_zval(&info, &opob);
    }

    add_property_zval(&archob, "operands", &info);

    add_property_zval(pdetailob, "x86", &archob);
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
    cs_handle->arch = (cs_arch)arch;
    cs_handle->mode = (cs_mode)mode;

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
            cs_insn *ins = &(insn[j]);
            zval bytesar;
            int n;

            object_init(&instob);

            add_property_long(&instob, "address", ins->address);
            add_property_string(&instob, "mnemonic", ins->mnemonic);
            add_property_string(&instob, "op_str", ins->op_str);

            array_init(&bytesar);
            for (n = 0; n < ins->size; n++) {
                add_next_index_long(&bytesar, ins->bytes[n]);
            }
            add_property_zval(&instob, "bytes", &bytesar);

            if (cs_handle->opt_detail) {
                zval detailob, archob, regsar;

                object_init(&detailob);

                array_init(&regsar);
                for (n = 0; n < ins->detail->regs_read_count; n++) {
                    add_next_index_string(&regsar, cs_reg_name(cs_handle->handle, ins->detail->regs_read[n]));
                }
                add_property_zval(&detailob, "regs_read", &regsar);

                array_init(&regsar);
                for (n = 0; n < ins->detail->regs_write_count; n++) {
                    add_next_index_string(&regsar, cs_reg_name(cs_handle->handle, ins->detail->regs_write[n]));
                }
                add_property_zval(&detailob, "regs_write", &regsar);

                array_init(&regsar);
                for (n = 0; n < ins->detail->groups_count; n++) {
                    add_next_index_string(&regsar, cs_group_name(cs_handle->handle, ins->detail->groups[n]));
                }
                add_property_zval(&detailob, "groups", &regsar);

                switch (cs_handle->arch) {
                    case CS_ARCH_X86:
                        arch_detail_x86(cs_handle, &detailob, &ins->detail->x86);
                        break;
                    default:
                        break;
                }

                add_property_zval(&instob, "detail", &detailob);
            }

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

    switch ((cs_opt_type)type) {
        case CS_OPT_DETAIL:
            if (value == CS_OPT_ON) {
                cs_handle->opt_detail = 1;
            } else if (value == CS_OPT_OFF) {
                cs_handle->opt_detail = 0;
            }
            break;
        case CS_OPT_SKIPDATA:
            if (value == CS_OPT_ON) {
                cs_handle->opt_skipdata = 1;
            } else if (value == CS_OPT_OFF) {
                cs_handle->opt_skipdata = 0;
            }
            break;
        case CS_OPT_MODE:
            cs_handle->mode = value;
            break;
        default:
            break;
    }

    RETURN_TRUE;
}
