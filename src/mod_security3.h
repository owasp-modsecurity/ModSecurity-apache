

#include <ctype.h>

#include <modsecurity/modsecurity.h>
#if defined(MODSECURITY_CHECK_VERSION)
#if MODSECURITY_VERSION_NUM >= 304010
#define MSC_USE_RULES_SET 1
#endif
#endif

#if defined(MSC_USE_RULES_SET)
#include <modsecurity/rules_set.h>
#else
#include <modsecurity/rules.h>
#endif
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
/* #define REQUEST_EARLY */
#define LATE_CONNECTION_PROCESS

#define N_INTERVENTION_STATUS 200


typedef struct
{
    request_rec *r;
    Transaction *t;
} msc_t;


typedef struct
{
    void *rules_set;
    int msc_state;
    char *name_for_debug;
} msc_conf_t;

typedef struct
{
    ModSecurity *modsec;
} msc_global;

extern module AP_MODULE_DECLARE_DATA security3_module;
extern msc_global *msc_apache;
extern const command_rec module_directives[];


int process_intervention (Transaction *t, request_rec *r);

int msc_apache_init(apr_pool_t *pool);
int msc_apache_cleanup();
static apr_status_t msc_module_cleanup(void *data);


/*

static int hook_connection_early(conn_rec *conn);

static int msc_hook_pre_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp);
static int msc_hook_post_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp, server_rec *s);

static int hook_request_late(request_rec *r);
static int hook_request_early(request_rec *r);
static int hook_log_transaction(request_rec *r);

static void hook_insert_filter(request_rec *r);
*/
/*
*/

static int process_request_headers(request_rec *r, msc_t *msr);

#endif /*  _SRC_APACHE_HTTP_MODSECURITY__ */
