#include "apache_http_modsecurity.h"

typedef struct conf_t {
    int enable_input;
    int enable_output;
} conf_t;

typedef struct {
  ModSecurity *modsec;
} apache_http_modsecurity_main_conf_t;

typedef struct {
    Rules *rules_set;
    char *rules;
    char *rules_file;
    const char *rules_remote_server;
    const char *rules_remote_key;
    int enable;
    int id;
} apache_http_modsecurity_loc_conf_t;

const char *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2)
{
    apache_http_modsecurity_loc_conf_t *cf = (apache_http_modsecurity_loc_conf_t *)cfg;    
    if(cf == NULL){
    	return "ModSecurity's remote_server processing directive didn't get an instance of the Apache config, we can't continue";
    }
    // Add checks here for p1 and p2 spec
    cf->rules_remote_key = p1;
    cf->rules_remote_server = p2;
    fprintf(stderr,"ModSecurity: License Key: %s, URI: %s\n", p1, p2);
    return NULL;
}

static const command_rec module_directives[] =
{
    AP_INIT_FLAG("modsecurity", ap_set_flag_slot, (void*)APR_OFFSETOF(apache_http_modsecurity_loc_conf_t,enable), OR_OPTIONS, "The argument must be either 'On' or 'Off'"),
    AP_INIT_TAKE1("modsecurity_rules_file", ap_set_string_slot, (void*)APR_OFFSETOF(apache_http_modsecurity_loc_conf_t,rules_file), OR_OPTIONS, "Load ModSecurity rules from a file"),
    AP_INIT_TAKE2("modsecurity_rules_remote", apache_http_modsecurity_set_remote_server, NULL, OR_OPTIONS, "Load ModSecurity rules from a remote server"),
    AP_INIT_TAKE1("modsecurity_rules", ap_set_string_slot, (void*)APR_OFFSETOF(apache_http_modsecurity_loc_conf_t,rules), OR_OPTIONS, "Please ensure that the arugment is specified correctly, including line continuations."),
    AP_INIT_FLAG("IOInput", enable_input, NULL, RSRC_CONF, "Enable Input Data"),
    AP_INIT_FLAG("IOOutput", enable_output, NULL, RSRC_CONF, "Enable Output Data"),
    { NULL }
};


module AP_MODULE_DECLARE_DATA security3_module  =
{
    STANDARD20_MODULE_STUFF,
    apache_http_modsecurity_create_loc_conf, // Per-directory configuration
    apache_http_modsecurity_merge_loc_conf, // Merge handler for per-directory
    apache_http_modsecurity_create_main_conf, // Per-server conf handler
    NULL,            // Merge handler for per-server configurations
    module_directives,
    register_hooks   
};

static void* apache_http_modsecurity_merge_loc_conf(apr_pool_t* pool, void* parent, void* child) {
    fprintf(stderr,"Merge Request was called\n\n");
    apache_http_modsecurity_loc_conf_t *p = NULL;
    apache_http_modsecurity_loc_conf_t *c = NULL;
    apache_http_modsecurity_loc_conf_t *conf = apr_palloc(pool, sizeof(apache_http_modsecurity_loc_conf_t));
    p = parent;
    c = child;
    conf = p;
    fprintf(stderr,"Rules set: '%p'\n", conf->rules_set);
    if (p->rules_set != NULL)
    {
    	fprintf(stderr,"We have parental data");
        fprintf(stderr,"Parent is not null, so we have to merge this configurations");
        msc_rules_merge(c->rules_set, p->rules_set);
    }
    
    if (c->rules_remote_server != NULL)
    {
        int res;
        const char *error = NULL;
        res = msc_rules_add_remote(c->rules_set, c->rules_remote_key, c->rules_remote_server, &error);
        fprintf(stderr,"Loading rules from: '%s'", c->rules_remote_server);
        if (res < 0) {
            fprintf("Failed to load the rules from: '%s'  - reason: '%s'", c->rules_remote_server, error);

            return strdup(error);
        }
        fprintf(stderr,"Loaded '%d' rules.", res);
    }

    if (c->rules_file != NULL)
    {
        int res;
        const char *error = NULL;
        res = msc_rules_add_file(c->rules_set, c->rules_set, &error);
        fprintf(stderr,"Loading rules from: '%s'", c->rules_set);
        if (res < 0) {
            fprintf(stderr,"Failed to load the rules from: '%s' - reason: '%s'", c->rules_set, error);
            return strdup(error);
        }
        fprintf(stderr,"Loaded '%d' rules.", res);
    }

    if (c->rules != NULL)
    {
        int res;
        const char *error = NULL;
        res = msc_rules_add(c->rules_set, c->rules, &error);
        fprintf(stderr,"Loading rules: '%s'", c->rules);
        if (res < 0) {
            fprintf(stderr,"Failed to load the rules: '%s' - reason: '%s'", c->rules, error);
            return strdup(error);
        }
    }
    msc_rules_dump(c->rules_set);
    return conf;
}

void *apache_http_modsecurity_create_main_conf(apr_pool_t* pool, server_rec* svr) {
    conf_t *ptr = apr_pcalloc(pool, sizeof *ptr);
    ptr->enable_input = 0;
    ptr->enable_output = 0;
    return ptr;
    
}

void *apache_http_modsecurity_create_loc_conf(apr_pool_t *mp, char *path){

    apache_http_modsecurity_loc_conf_t  *cf;
    cf = (apache_http_modsecurity_loc_conf_t  *)apr_palloc(mp, sizeof(apache_http_modsecurity_loc_conf_t));
    if (cf == NULL)
    {
	fprintf(stderr,"Couldn't allocate space for our location specific configurations");
        return NULL;
    }

    cf->rules_set = msc_create_rules_set();
    cf->rules_file = NULL;
    cf->rules_remote_server = NULL;
    cf->rules_remote_key = NULL;
    cf->enable = 1;
    cf->id = 0;
    fprintf(stderr,"ModSecurity creating a location configurationn\n");
    msc_rules_dump(cf->rules_set);

    return cf;
}

static void register_hooks(apr_pool_t *pool) 
{
    ap_hook_handler(modsec_handler, NULL, NULL, APR_HOOK_LAST);
    ap_hook_pre_connection(pre_conn, NULL, NULL, APR_HOOK_FIRST);
    ap_register_output_filter("OUT", output_filter, NULL, AP_FTYPE_CONNECTION + 3) ;
    ap_register_input_filter("IN", input_filter, NULL, AP_FTYPE_CONNECTION + 3) ;
}

static int modsec_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "mod-basics")) return (DECLINED);
    ap_rputs("Welcome to ModSec!<br/>", r);
    return OK;
}

static const char *enable_input(cmd_parms *cmd, void *v, int i)
{
    conf_t *ptr = ap_get_module_config(cmd->server->module_config, &security3_module);

    ptr->enable_input = i;
    return NULL;
}

static const char *enable_output(cmd_parms *cmd, void *v, int i)
{
    conf_t *ptr = ap_get_module_config(cmd->server->module_config, &security3_module);

    ptr->enable_output = i;
    return NULL;
}

static int pre_conn(conn_rec *c)
{
    conf_t *ptr;
    ptr = (conf_t *) ap_get_module_config(c->base_server->module_config, &security3_module);

    if (ptr->enable_input)
        ap_add_input_filter("IN", ptr, NULL, c);
    if (ptr->enable_output)
        ap_add_output_filter("OUT", ptr, NULL, c);
    return OK;
}

static int input_filter (ap_filter_t *f, apr_bucket_brigade *bb,
    ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *b;
    apr_status_t ret;
    conn_rec *c = f->c;
    conf_t *ptr = f->ctx;

    ret = ap_get_brigade(f->next, bb, mode, block, readbytes);

    if (ret == APR_SUCCESS) {
        for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
          //Next
        }
    }
    else {
                return ret;
    }

    return APR_SUCCESS ;
}

static int output_filter (ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    conn_rec *c = f->c;
    conf_t *ptr = f->ctx;

    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
       
        if (APR_BUCKET_IS_EOS(b)) {
            apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
            APR_BUCKET_INSERT_BEFORE(b, flush);
        }
        //Next
    }

    return ap_pass_brigade(f->next, bb) ;
}
