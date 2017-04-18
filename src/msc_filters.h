

#ifndef _SRC_MSC_FILTERS__
#define _SRC_MSC_FILTERS__

static void *FilterInCreateServerConfig(apr_pool_t *p, server_rec *s);
static void *FilterOutCreateServerConfig(apr_pool_t *p, server_rec *s);
static const char *FilterInEnable(cmd_parms *cmd, void *dummy, int arg);
static const char *FilterOutEnable(cmd_parms *cmd, void *dummy, int arg);
static int output_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn);
static int input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut, ap_input_mode_t eMode,
                        apr_read_type_e eBlock, apr_off_t nBytes);

static void InputFilter(request_rec *r);
static void OutputFilter(request_rec *r);

#endif  /* _SRC_MSC_FILTERS__ */
