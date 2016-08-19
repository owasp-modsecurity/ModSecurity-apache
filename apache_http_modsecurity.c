#include "apache_http_modsecurity.h"

static const command_rec module_directives[] =
        {
                AP_INIT_FLAG("modsecurity", ap_set_flag_slot,
                             (void *) APR_OFFSETOF(apache_http_modsecurity_loc_conf_t, enable), OR_OPTIONS,
                             "The argument must be either 'On' or 'Off'"),
                AP_INIT_TAKE1("modsecurity_rules_file", ap_set_string_slot,
                              (void *) APR_OFFSETOF(apache_http_modsecurity_loc_conf_t, rules_file), OR_OPTIONS,
                              "Load ModSecurity rules from a file"),
                AP_INIT_TAKE2("modsecurity_rules_remote", apache_http_modsecurity_set_remote_server, NULL, OR_OPTIONS,
                              "Load ModSecurity rules from a remote server"),
                AP_INIT_TAKE1("modsecurity_rules", ap_set_string_slot,
                              (void *) APR_OFFSETOF(apache_http_modsecurity_loc_conf_t, rules), OR_OPTIONS,
                              "Please ensure that the arugment is specified correctly, including line continuations."),
                AP_INIT_FLAG("IN", FilterInEnable, NULL, RSRC_CONF, "Enable Input Data"),
                AP_INIT_FLAG("OUT", FilterOutEnable, NULL, RSRC_CONF, "Enable Output Data"),
                {NULL}
        };

const char *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2) {
    apache_http_modsecurity_loc_conf_t *cf = (apache_http_modsecurity_loc_conf_t *) cfg;
    if (cf == NULL) {
        return "ModSecurity's remote_server processing directive didn't get an instance of the Apache config, we can't continue";
    }
    // Add checks here for p1 and p2 spec
    cf->rules_remote_key = p1;
    cf->rules_remote_server = p2;
    fprintf(stderr, "ModSecurity: License Key: %s, URI: %s\n", p1, p2);
    return NULL;
}

static void *apache_http_modsecurity_merge_loc_conf(apr_pool_t *pool, void *parent, void *child) {
    fprintf(stderr, "Merge Request was called\n\n");
    apache_http_modsecurity_loc_conf_t *p = NULL;
    apache_http_modsecurity_loc_conf_t *c = NULL;
    apache_http_modsecurity_loc_conf_t *conf = apr_palloc(pool, sizeof(apache_http_modsecurity_loc_conf_t));
    p = parent;
    c = child;
    conf = p;
    fprintf(stderr, "Rules set: '%p'\n", conf->rules_set);
    if (p->rules_set != NULL) {
        fprintf(stderr, "We have parental data");
        fprintf(stderr, "Parent is not null, so we have to merge this configurations");
        msc_rules_merge(c->rules_set, p->rules_set);
    }

    if (c->rules_remote_server != NULL) {
        int res;
        const char *error = NULL;
        res = msc_rules_add_remote(c->rules_set, c->rules_remote_key, c->rules_remote_server, &error);
        fprintf(stderr, "Loading rules from: '%s'", c->rules_remote_server);
        if (res < 0) {
            fprintf("Failed to load the rules from: '%s'  - reason: '%s'", c->rules_remote_server, error);

            return strdup(error);
        }
        fprintf(stderr, "Loaded '%d' rules.", res);
    }

    if (c->rules_file != NULL) {
        int res;
        const char *error = NULL;
        res = msc_rules_add_file(c->rules_set, c->rules_set, &error);
        fprintf(stderr, "Loading rules from: '%s'", c->rules_set);
        if (res < 0) {
            fprintf(stderr, "Failed to load the rules from: '%s' - reason: '%s'", c->rules_set, error);
            return strdup(error);
        }
        fprintf(stderr, "Loaded '%d' rules.", res);
    }

    if (c->rules != NULL) {
        int res;
        const char *error = NULL;
        res = msc_rules_add(c->rules_set, c->rules, &error);
        fprintf(stderr, "Loading rules: '%s'", c->rules);
        if (res < 0) {
            fprintf(stderr, "Failed to load the rules: '%s' - reason: '%s'", c->rules, error);
            return strdup(error);
        }
    }
    msc_rules_dump(c->rules_set);
    return conf;
}

void *apache_http_modsecurity_create_main_conf(apr_pool_t *pool, server_rec *svr) {
    
   // return 1;

}

void *apache_http_modsecurity_create_loc_conf(apr_pool_t *mp, char *path) {

    apache_http_modsecurity_loc_conf_t *cf;
    cf = (apache_http_modsecurity_loc_conf_t *) apr_palloc(mp, sizeof(apache_http_modsecurity_loc_conf_t));
    if (cf == NULL) {
        fprintf(stderr, "Couldn't allocate space for our location specific configurations");
        return NULL;
    }

    cf->rules_set = msc_create_rules_set();
    cf->rules_file = NULL;
    cf->rules_remote_server = NULL;
    cf->rules_remote_key = NULL;
    cf->enable = 1;
    cf->id = 0;
    fprintf(stderr, "ModSecurity creating a location configurationn\n");
    char uri[] = "/opt/ModSecurity/examples/multiprocess_c/basic_rules.conf";
    const char *err = NULL;
    int ret = msc_rules_add_file(cf->rules_set, uri, &err);
    fprintf(stderr, "Total Rules '%d' \n",ret);
    msc_rules_dump(cf->rules_set);

    return cf;
}

static void register_hooks(apr_pool_t *pool) {
    ap_hook_handler(modsec_handler, NULL, NULL, APR_HOOK_FIRST);
 //   ap_hook_pre_connection(pre_con, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_insert_filter(OutputFilter, NULL, NULL, APR_HOOK_FIRST);
    ap_register_output_filter("OUT", output_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_insert_filter(InputFilter, NULL, NULL, APR_HOOK_FIRST);
    ap_register_input_filter("IN", input_filter, NULL, AP_FTYPE_RESOURCE);
}

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

static void OutputFilter(request_rec *r)
{
    FilterConfig *pConfig = ap_get_module_config(r->server->module_config, &security3_module);

    if (!pConfig->oEnabled)
        return;

    ap_add_output_filter("OUT", NULL, r, r->connection);
}

static void InputFilter(request_rec *r)
{
    FilterConfig *pConfig = ap_get_module_config(r->server->module_config, &security3_module);
    if (!pConfig->iEnabled)
        return;

    ap_add_input_filter("IN", NULL, r, r->connection);
}

static int modsec_handler(request_rec *r) {
    if (!r->handler || strcmp(r->handler, "libModSec")) return (DECLINED);
    ap_rputs("Welcome to ModSec!<br/>", r);
    return OK;
}



static void *FilterOutCreateServerConfig(apr_pool_t *p, server_rec *s)
{
    FilterConfig *pConfig = apr_pcalloc(p,sizeof *pConfig);

    pConfig->oEnabled = 1;

    return pConfig;
}

static void *FilterInCreateServerConfig(apr_pool_t *p, server_rec *s)
{
    FilterConfig *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->iEnabled = 1;

    return pConfig;
}

static int input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut,
                        ap_input_mode_t eMode, apr_read_type_e eBlock, apr_off_t nBytes) {

    request_rec *r = f->r;
    conn_rec *c = r->connection;
    FilterContext *pCtx;
    apr_status_t ret;

    if (!(pCtx = f->ctx)) {
        f->ctx = pCtx = apr_palloc(r->pool, sizeof *pCtx);
        pCtx->pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    if (APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        ret = ap_get_brigade(f->next, pCtx->pbbTmp, eMode, eBlock, nBytes);

        if (eMode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
            return ret;
    }

    while (!APR_BRIGADE_EMPTY(pCtx->pbbTmp)) {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pCtx->pbbTmp);
        apr_bucket *pbktOut;
        const char *data;
        apr_size_t len;
        char *buf;
        apr_size_t n;

        if (APR_BUCKET_IS_EOS(pbktIn)) {
            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            break;
        }

        ret=apr_bucket_read(pbktIn, &data, &len, eBlock);
        if (ret != APR_SUCCESS)
            return ret;

        buf = ap_malloc(len);
        for (n=0 ; n < len ; ++n) {
            buf[n] = data[n];
        }

        pbktOut = apr_bucket_heap_create(buf, len, 0, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
        apr_bucket_delete(pbktIn);
    }

    return APR_SUCCESS;
}

static int output_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
    
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;

    pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);
    for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
         pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
         pbktIn = APR_BUCKET_NEXT(pbktIn))
    {
        const char *data;
        apr_size_t len;
        char *buf;
        apr_size_t n;
        apr_bucket *pbktOut;

        if (APR_BUCKET_IS_EOS(pbktIn)) {
            apr_bucket *pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktEOS);
            continue;
        }

        apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);

        buf = apr_bucket_alloc(len, c->bucket_alloc);
        for (n=0 ; n < len ; ++n) {
            buf[n] = data[n];
        }

        pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
    }

    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next, pbbOut);
}

module AP_MODULE_DECLARE_DATA security3_module =
        {
                STANDARD20_MODULE_STUFF,
                apache_http_modsecurity_create_loc_conf, // Per-directory configuration
                apache_http_modsecurity_merge_loc_conf, // Merge handler for per-directory
                apache_http_modsecurity_create_main_conf, // Per-server conf handler
                NULL,            // Merge handler for per-server configurations
                module_directives,
                register_hooks
        };
