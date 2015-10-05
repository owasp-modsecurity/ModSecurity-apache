#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"

static void register_hooks(apr_pool_t *pool);
static int modsec_handler(request_rec *r);
const char  *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2);



const char *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2)
{
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
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    module_directives,
    register_hooks   
};



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
