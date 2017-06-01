
#ifndef _SRC_MSC_CONFIG__
#define _SRC_MSC_CONFIG__

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

static const char *msc_config_modsec_state(cmd_parms *cmd, void *_dcfg,
    const char *p1);

static const char *msc_config_load_rules(cmd_parms *cmd, void *_dcfg,
    const char *p1);

static const char *msc_config_load_rules_file(cmd_parms *cmd, void *_dcfg,
    const char *p1);

static const char *msc_config_load_rules_remote(cmd_parms *cmd, void *_dcfg,
    const char *p1, const char *p2);


#endif  /* _SRC_MSC_CONFIG__ */
