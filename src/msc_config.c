
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

    if (ret < 0)
    {
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

    if (ret < 0)
    {
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

    if (ret < 0)
    {
        return error;
    }

    return NULL;
}

void *msc_hook_create_config_directory(apr_pool_t *mp, char *path)
{
    msc_conf_t *cnf = NULL;

    cnf = apr_pcalloc(mp, sizeof(msc_conf_t));
    if (cnf == NULL)
    {
        goto end;
    }
#if 0
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Created directory config for path: %s [%pp]", path, cnf);
#endif

    cnf->rules_set = msc_create_rules_set();
    if (path != NULL)
    {
        cnf->name_for_debug = strdup(path);
    }
#if 0
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Config for path: %s is at: %pp", path, cnf);
#endif

end:
    return cnf;
}


void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child)
{
    msc_conf_t *cnf_p = parent;
    msc_conf_t *cnf_c = child;
    msc_conf_t *cnf_new = (msc_conf_t *)msc_hook_create_config_directory(mp, cnf_c->name_for_debug);

    if (cnf_p && cnf_c)
    {
        const char *error = NULL;
        int ret;
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child %pp [%s]" \
            "into: %pp", cnf_p,
            cnf_p->name_for_debug,
            child, cnf_c->name_for_debug, cnf_new);
#endif
        cnf_new->name_for_debug = cnf_c->name_for_debug;

        ret = msc_rules_merge(cnf_new->rules_set, cnf_c->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Rule merge failed: %s", error);
            return NULL;
        }

        ret = msc_rules_merge(cnf_new->rules_set, cnf_p->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Rule merge failed: %s", error);
            return NULL;
        }
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Merge OK");
#endif
    }
    else if (cnf_c && !cnf_p)
    {
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent -NULL- [-NULL-] child %pp [%s]",
            cnf_c, cnf_c->name_for_debug);
#endif
    }
    else if (cnf_p && !cnf_c)
    {
#if 0
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child -NULL- [-NULL-]",
            cnf_p, cnf_p->name_for_debug);
#endif
    }

    return cnf_new;
}
