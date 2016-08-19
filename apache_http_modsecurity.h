#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"
#include "http_log.h"
#include "ap_expr.h"
#include "apr.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "mod_ssl.h"
#include <ctype.h>
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

//static int pre_con(conn_rec *c);
static void *FilterInCreateServerConfig(apr_pool_t *p, server_rec *s);
static void *FilterOutCreateServerConfig(apr_pool_t *p, server_rec *s);
static const char *FilterInEnable(cmd_parms *cmd, void *dummy, int arg);
static const char *FilterOutEnable(cmd_parms *cmd, void *dummy, int arg);
static int output_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn);
static int input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut, ap_input_mode_t eMode, apr_read_type_e eBlock, apr_off_t nBytes);
static void InputFilter(request_rec *r);
static void OutputFilter(request_rec *r);

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

typedef struct
{
    int iEnabled; 
    int oEnabled;
} FilterConfig;

typedef struct
{
    apr_bucket_brigade *pbbTmp;
} FilterContext;

