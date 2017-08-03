
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

#include "http_core.h"
#include "http_request.h"
#include "httpd.h"
#include "ap_release.h"

#include <apr_general.h>
#include <apr_optional.h>

#ifndef _SRC_MSC_UTILS__
#define _SRC_MSC_UTILS__

#include "mod_security3.h"


int id(const char *fn, const char *format, ...);


apr_status_t send_error_bucket(msc_t *msr, ap_filter_t *f, int status);


#endif  /* _SRC_MSC_UTILS__ */
