
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


static const char *cmd_msc_take1(cmd_parms *cmd, void *_dcfg, const char *p1);

static const char *cmd_msc_take12(cmd_parms *cmd, void *_dcfg, const char *p1,
    const char *p2);

static const char *cmd_msc_take2(cmd_parms *cmd, void *_dcfg, const char *p1,
    const char *p2);

static const char *cmd_msc_take23(cmd_parms *cmd, void *_dcfg, const char *p1,
    const char *p2, const char *p3);

static const char *cmd_msc_flag(cmd_parms *cmd, void *_dcfg, int flag);
static const char *cmd_msc_iterate(cmd_parms *cmd, void *_dcfg,
    const char *_p1);

static const char *cmd_msc_no_args(cmd_parms *cmd, void *_dcfg);


#endif  /* _SRC_MSC_CONFIG__ */
