#include "apache_http_modsecurity.h"

const command_rec module_directives[] =
{
    AP_INIT_FLAG("modsecurity",
    ap_set_flag_slot,
    (void *) APR_OFFSETOF(apache_http_modsecurity_loc_conf_t, enable),
    OR_OPTIONS,
    "The argument must be either 'On' or 'Off'"),

    AP_INIT_TAKE1("modsecurity_rules_file",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(apache_http_modsecurity_loc_conf_t,
    rules_file),
    OR_OPTIONS,
    "Load ModSecurity rules from a file"),

    AP_INIT_TAKE2("modsecurity_rules_remote",
    apache_http_modsecurity_set_remote_server,
    NULL,
    OR_OPTIONS,
    "Load ModSecurity rules from a remote server"),

    AP_INIT_TAKE1("modsecurity_rules_path",
    apache_http_modsecurity_set_file_path,
    NULL,
    OR_OPTIONS,
    "Load ModSecurity rules from a path"),

    AP_INIT_TAKE1("modsecurity_rules",
    ap_set_string_slot,
    (void *) APR_OFFSETOF(apache_http_modsecurity_loc_conf_t, rules),
    OR_OPTIONS,
    "Please ensure that the arugment is specified correctly, including line continuations."),

    AP_INIT_FLAG("IN",
    FilterInEnable,
    NULL,
    RSRC_CONF,
    "Enable Input Data"),

    AP_INIT_FLAG("OUT",
    FilterOutEnable,
    NULL,
    RSRC_CONF,
    "Enable Output Data"),

    {NULL}
};

static const char *FilterInEnable(cmd_parms *cmd, void *dummy, int arg)
{
    FilterConfig *pConfig = ap_get_module_config(cmd->server->module_config, &security3_module);
    pConfig->iEnabled=arg;

    return NULL;
}

static const char *FilterOutEnable(cmd_parms *cmd, void *dummy, int arg)
{
    FilterConfig *pConfig = ap_get_module_config(cmd->server->module_config, &security3_module);
    pConfig->oEnabled=arg;

    return NULL;
}
