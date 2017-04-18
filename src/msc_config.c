
#include "apache_http_modsecurity.h"
#include "msc_config.h"
#include "msc_filters.h"

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


const char *apache_http_modsecurity_set_remote_server(cmd_parms *cmd,
        void *cfg,
        const char *p1,
        const char *p2)
{
    apache_http_modsecurity_loc_conf_t *cf = (apache_http_modsecurity_loc_conf_t *) cfg;
    if (cf == NULL)
    {
        return "ModSecurity's remote_server processing directive didn't get an instance.";
    }
    // Add checks here for p1 and p2 spec
    cf->rules_remote_key = p1;
    cf->rules_remote_server = p2;
    fprintf(stderr, "ModSecurity: License Key: %s, URI: %s\n", p1, p2);
    return NULL;
}


const char *apache_http_modsecurity_set_file_path(cmd_parms *cmd,
        void *cfg,
        const char *p)
{
    apache_http_modsecurity_loc_conf_t *cf = (apache_http_modsecurity_loc_conf_t *) cfg;
    if (cf == NULL)
    {
        return "ModSecurity's remote_server processing directive didn't get an instance.";
    }

    cf->rules_set = msc_create_rules_set();
    cf->rules_file = NULL;
    cf->rules_remote_server = NULL;
    cf->rules_remote_key = NULL;
    cf->enable = 1;
    cf->id = 0;
    fprintf(stderr, "ModSecurity creating a location configurationn\n");
    char uri[100] ;
    strcpy(uri,p);
    const char *err = NULL;
    int ret = msc_rules_add_file(cf->rules_set, uri, &err);
    fprintf(stderr, "Total Rules '%d' \n",ret);
    msc_rules_dump(cf->rules_set);

    return NULL;
}


static void *apache_http_modsecurity_merge_loc_conf(apr_pool_t *pool,
        void *parent,
        void *child)
{
    fprintf(stderr, "Merge Request was called\n\n");
    /*
    apache_http_modsecurity_loc_conf_t *p = NULL;
    apache_http_modsecurity_loc_conf_t *c = NULL;
    apache_http_modsecurity_loc_conf_t *conf = apr_palloc(pool,
            sizeof(apache_http_modsecurity_loc_conf_t));

    p = parent;
    c = child;
    conf = p;
    fprintf(stderr, "Rules set: '%p'\n", conf->rules_set);
    if (p->rules_set != NULL)
    {
	const char *error = NULL;
        fprintf(stderr, "We have parental data");
        fprintf(stderr, "Parent is not null, so we have to merge this configurations");
        msc_rules_merge(c->rules_set, p->rules_set, &error);
    }

    if (c->rules_remote_server != NULL)
    {
        int res;
        const char *error = NULL;
        res = msc_rules_add_remote(c->rules_set, c->rules_remote_key, c->rules_remote_server, &error);
        fprintf(stderr, "Loading rules from: '%s'", c->rules_remote_server);
        if (res < 0)
        {
            fprintf(stderr, "Failed to load the rules from: '%s'  - reason: '%s'", c->rules_remote_server, error);

            return strdup(error);
        }
        fprintf(stderr, "Loaded '%d' rules.", res);
    }

    if (c->rules_file != NULL)
    {
        int res;
        const char *error = NULL;
        res = msc_rules_add_file(c->rules_set, c->rules_file, &error);
        fprintf(stderr, "Loading rules from: '%s'", c->rules_file);
        if (res < 0)
        {
            fprintf(stderr, "Failed to load the rules from: '%s' - reason: '%s'", c->rules_file, error);
            return strdup(error);
        }
        fprintf(stderr, "Loaded '%d' rules.", res);
    }

    if (c->rules != NULL)
    {
        int res;
        const char *error = NULL;
        res = msc_rules_add(c->rules_set, c->rules, &error);
        fprintf(stderr, "Loading rules: '%s'", c->rules);
        if (res < 0)
        {
            fprintf(stderr, "Failed to load the rules: '%s' - reason: '%s'", c->rules, error);
            return strdup(error);
        }
    }
    msc_rules_dump(c->rules_set);
    */
    return child;
}

