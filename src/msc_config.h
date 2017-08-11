
#ifndef _SRC_MSC_CONFIG__
#define _SRC_MSC_CONFIG__

static const char *msc_config_modsec_state(cmd_parms *cmd, void *_dcfg,
    const char *p1);

static const char *msc_config_load_rules(cmd_parms *cmd, void *_dcfg,
    const char *p1);

static const char *msc_config_load_rules_file(cmd_parms *cmd, void *_dcfg,
    const char *p1);

static const char *msc_config_load_rules_remote(cmd_parms *cmd, void *_dcfg,
    const char *p1, const char *p2);

void *msc_hook_create_config_directory(apr_pool_t *mp, char *path);

void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child);



#endif  /* _SRC_MSC_CONFIG__ */
