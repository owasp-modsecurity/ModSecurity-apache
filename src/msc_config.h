
#ifndef _SRC_MSC_CONFIG__
#define _SRC_MSC_CONFIG__

static const char *FilterInEnable(cmd_parms *cmd, void *dummy, int arg);
static const char *FilterOutEnable(cmd_parms *cmd, void *dummy, int arg);
const char *apache_http_modsecurity_set_remote_server(cmd_parms *cmd,
        void *cfg,
        const char *p1,
        const char *p2);

const char *apache_http_modsecurity_set_file_path(cmd_parms *cmd,
        void *cfg,
        const char *p);

static void *apache_http_modsecurity_merge_loc_conf(apr_pool_t *pool,
        void *parent,
        void *child);


#endif  /* _SRC_MSC_CONFIG__ */
