#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_connection.h"
#include "http_log.h"
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


#ifndef _SRC_APACHE_HTTP_MODSECURITY__
#define _SRC_APACHE_HTTP_MODSECURITY__



extern module AP_MODULE_DECLARE_DATA security3_module;

extern const command_rec module_directives[];


int msc_apache_init(apr_pool_t *pool);
int msc_apache_cleanup();

static apr_status_t msc_module_cleanup(void *data);

static int msc_hook_pre_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp);
static int msc_hook_post_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp, server_rec *s);
static void msc_register_hooks(apr_pool_t *pool);

void *msc_hook_create_config_directory(apr_pool_t *mp, char *path);
static void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child);


typedef struct
{
    ModSecurity *modsec;
} msc_t;


typedef struct
{
    Rules *rules_set;
    int msc_state;
} msc_conf_t;





typedef struct
{
    ModSecurity *modsec;
    Transaction *transaction;
} apache_http_modsecurity_main_conf_t;



typedef struct
{
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


#endif /*  _SRC_APACHE_HTTP_MODSECURITY__ */
