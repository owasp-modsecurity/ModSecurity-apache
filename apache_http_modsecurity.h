#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"
#include "apr_strings.h"
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

module AP_MODULE_DECLARE_DATA security3_module;

static void register_hooks(apr_pool_t *pool);
static int modsec_handler(request_rec *r);
void *apache_http_modsecurity_create_loc_conf(apr_pool_t *mp, char *path);
void *apache_http_modsecurity_create_main_conf(apr_pool_t* pool, server_rec* svr);
static void* apache_http_modsecurity_merge_loc_conf(apr_pool_t* pool, void* parent, void* child);
const char  *apache_http_modsecurity_set_remote_server(cmd_parms *cmd, void *cfg, const char *p1, const char *p2);

static int pre_conn(conn_rec *c);
static const char *enable_input(cmd_parms *cmd, void *v, int i);
static const char *enable_output(cmd_parms *cmd, void *v, int i);
static int output_filter (ap_filter_t *f, apr_bucket_brigade *bb);
static int input_filter (ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes);
