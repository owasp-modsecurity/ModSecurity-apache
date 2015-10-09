#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include <modsecurity/modsecurity.h>
#include <modsecurity/assay.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

module AP_MODULE_DECLARE_DATA security3_module;

static void register_hooks(apr_pool_t *pool);
static int modsec_handler(request_rec *r);
void *apache_http_modsecurity_create_loc_conf(apr_pool_t *mp, char *path);
void *apache_http_modsecurity_create_main_conf(apr_pool_t* pool, server_rec* svr);
const char  *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2);

typedef struct {
  ModSecurity *modsec;
} apache_http_modsecurity_main_conf_t;


typedef struct {
    Rules *rules_set;
    char *rules_file;
    const char *rules_remote_server;
    const char *rules_remote_key;

    int enable;
    int id;

    //Rules *rules_set;
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
    AP_INIT_FLAG("modsecurity", ap_set_flag_slot, NULL, OR_OPTIONS, "Turn ModSecurity on or off"),
    AP_INIT_TAKE1("modsecurity_rules_file", ap_set_string_slot, NULL, OR_OPTIONS, "Load ModSecurity rules from a file"),
    AP_INIT_TAKE2("modsecurity_rules_remote", apache_http_modsecurity_set_remote_server, NULL, OR_OPTIONS, "Load ModSecurity rules from a remote server"),
    AP_INIT_TAKE1("modsecurity_rules", ap_set_string_slot, NULL, OR_OPTIONS, "Specify ModSecurity rules inline"),
    { NULL }
};


module AP_MODULE_DECLARE_DATA   security3_module  =
{
    STANDARD20_MODULE_STUFF,
    apache_http_modsecurity_create_loc_conf, // Per-directory configuration
    NULL,            // Merge handler for per-directory configurations
    apache_http_modsecurity_create_main_conf, // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    module_directives,
    register_hooks   
};

void *apache_http_modsecurity_create_main_conf(apr_pool_t* pool, server_rec* svr) {
    // This doesn't really do anything right now...
    apache_http_modsecurity_main_conf_t *config = apr_pcalloc(pool, sizeof(apache_http_modsecurity_main_conf_t));
    config->modsec = msc_init();
    if(config->modsec != NULL){
    	fprintf(stderr,"ModSecurity: We were unable to initalize the ModSecurity library, skipping hooks\n");
    	return NULL;
    }else{
    	fprintf(stderr,"ModSecurity: Started Life");
    }
    msc_set_connector_info(config->modsec, "ModSecurity-apache v0.0.1-alpha");
    //msc_set_log_cb(config.modsec, ngx_http_modsecurity_log);
    return config;
    
}

void *apache_http_modsecurity_create_loc_conf(apr_pool_t *mp, char *path){

    apache_http_modsecurity_loc_conf_t  *cf;
    cf = (apache_http_modsecurity_loc_conf_t  *)
        apr_palloc(mp, sizeof(apache_http_modsecurity_loc_conf_t));
    if (cf == NULL)
    {
        return NULL;
    }

    cf->rules_set = msc_create_rules_set();
    cf->rules_file = NULL;
    cf->rules_remote_server = NULL;
    cf->rules_remote_key = NULL;
    // Figure out what to set this too
    cf->enable = 1;
    cf->id = 0;
    fprintf(stderr,"ModSecurity creating a location configuration\n");
    msc_rules_dump(cf->rules_set);

    return cf;
}

static void register_hooks(apr_pool_t *pool) 
{
    ap_hook_handler(modsec_handler, NULL, NULL, APR_HOOK_LAST);
}

static int modsec_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "mod-basics")) return (DECLINED);
    ap_rputs("Welcome to ModSec!<br/>", r);
    return OK;
}
