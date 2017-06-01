
#include "mod_security3.h"
#include "msc_config.h"
#include "msc_filters.h"

const command_rec module_directives[] =
{
    AP_INIT_TAKE1(
        "modsecurity",
        msc_config_modsec_state,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "The argument must be either 'On' or 'Off'"
    ),

    AP_INIT_TAKE1(
        "modsecurity_rules",
        msc_config_load_rules,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "Please ensure that the arugment is specified correctly, including line continuations."
    ),

    AP_INIT_TAKE1(
        "modsecurity_rules_file",
        msc_config_load_rules_file,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "Load ModSecurity rules from a file"
    ),

    AP_INIT_TAKE2(
        "modsecurity_rules_remote",
        msc_config_load_rules_remote,
        NULL,
        RSRC_CONF | ACCESS_CONF,
        "Load ModSecurity rules from a remote server"
    ),

    {NULL}
};


static const char *msc_config_modsec_state(cmd_parms *cmd, void *_cnf,
    const char *p1)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;

    if (strcasecmp(p1, "On") == 0)
    {
        cnf->msc_state = 1;
    }
    else if (strcasecmp(p1, "Off") == 0)
    {
        cnf->msc_state = 0;
    }
    else
    {
        return "ModSecurity state must be either 'On' or 'Off'";
    }

    return NULL;
}


static const char *msc_config_load_rules(cmd_parms *cmd, void *_cnf,
    const char *p1)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;
    const char *error = NULL;
    int ret;

    ret = msc_rules_add(cnf->rules_set, p1, &error);

    if (ret < 0) {
        return error;
    }

    return NULL;
}


static const char *msc_config_load_rules_file(cmd_parms *cmd, void *_cnf,
    const char *p1)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;
    const char *error = NULL;
    int ret;

    ret = msc_rules_add_file(cnf->rules_set, p1, &error);

    if (ret < 0) {
        return error;
    }

    return NULL;
}


static const char *msc_config_load_rules_remote(cmd_parms *cmd, void *_cnf,
    const char *p1, const char *p2)
{
    msc_conf_t *cnf = (msc_conf_t *) _cnf;
    const char *error = NULL;
    int ret;

    ret = msc_rules_add_remote(cnf->rules_set, p1, p2, &error);

    if (ret < 0) {
        return error;
    }

    return NULL;
}


