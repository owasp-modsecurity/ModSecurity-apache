#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include <modsecurity/modsecurity.h>
//#include <modsecurity/assay.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

module AP_MODULE_DECLARE_DATA security3_module;

static void register_hooks(apr_pool_t *pool);
static int modsec_handler(request_rec *r);
void *apache_http_modsecurity_create_loc_conf(apr_pool_t *mp, char *path);
void *apache_http_modsecurity_create_main_conf(apr_pool_t* pool, server_rec* svr);
static void* apache_http_modsecurity_merge_loc_conf(apr_pool_t* pool, void* parent, void* child);
const char  *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2);
