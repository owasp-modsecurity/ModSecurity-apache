

#include <ctype.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

#include "apr_buckets.h"
#include "apr_general.h"
#include "apr.h"
#include "apr_hash.h"
#include "apr_lib.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "util_filter.h"

#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "msc_filters.h"

#ifndef _SRC_APACHE_HTTP_MODSECURITY__
#define _SRC_APACHE_HTTP_MODSECURITY__

#define NOTE_MSR "modsecurity3-tx-context"
#define MSC_APACHE_CONNECTOR "ModSecurity-Apache v0.1.1-beta"
#define REQUEST_EARLY

#define N_INTERVENTION_STATUS 200

extern module AP_MODULE_DECLARE_DATA security3_module;
extern const command_rec module_directives[];

int process_intervention (Transaction *t, request_rec *r);

static void hook_insert_filter(request_rec *r);
int id(const char *fn, const char *format, ...);

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

static int hook_request_early(request_rec *r);

typedef struct
{
    ModSecurity *modsec;
    request_rec *r;
    Transaction *t;
} msc_t;


typedef struct
{
    Rules *rules_set;
    int msc_state;
    char *name_for_debug;
} msc_conf_t;


extern msc_t *msc_apache;


#endif /*  _SRC_APACHE_HTTP_MODSECURITY__ */
