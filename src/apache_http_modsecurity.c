#include "apache_http_modsecurity.h"
#include "apr.h"

extern const command_rec module_directives[];
msc_t *msc_apache;

#define MSC_APACHE_CONNECTOR "ModSecurity-Apache v0.1.1-beta"

/*
 * Called only once. Used to initialise the ModSecurity
 *
 */
int msc_apache_init(apr_pool_t *mp)
{
    msc_apache = apr_palloc(mp, sizeof(msc_t));
    if (msc_apache == NULL) {
        goto err_no_mem;
    }

    msc_apache->modsec = msc_init();

    msc_set_connector_info(msc_apache->modsec, MSC_APACHE_CONNECTOR);

    apr_pool_cleanup_register(mp, NULL, msc_module_cleanup, apr_pool_cleanup_null);

    return 0;

err_no_mem:
    return -1;
}

/*
 * Called only once. Used to cleanup ModSecurity
 *
 */
int msc_apache_cleanup()
{
    msc_cleanup(msc_apache->modsec);
}


static apr_status_t msc_module_cleanup(void *data)
{
    msc_apache_cleanup();
    return APR_SUCCESS;
}


static int msc_hook_pre_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp)
{
    void *data = NULL;
    const char *key = "modsecurity-pre-config-init-flag";
    int first_time = 0;

    /* Figure out if we are here for the first time */
    apr_pool_userdata_get(&data, key, mp);
    if (data == NULL) {
        apr_pool_userdata_set((const void *) 1, key,
                apr_pool_cleanup_null, mp);
        first_time = 1;
    }

    if (!first_time) {
        return OK;
    }


    // Code to run only at the very first call.
    int ret = msc_apache_init(mp);

    if (ret == -1) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                "ModSecurity: Failed to initialise.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return OK;
}


static int msc_hook_post_config(apr_pool_t *mp, apr_pool_t *mp_log,
    apr_pool_t *mp_temp, server_rec *s)
{
    void *data = NULL;
    const char *key = "modsecurity-post-config-init-flag";
    int first_time = 0;

    /* Figure out if we are here for the first time */
    apr_pool_userdata_get(&data, key, s->process->pool);
    if (data == NULL) {
        apr_pool_userdata_set((const void *) 1, key,
                apr_pool_cleanup_null, s->process->pool);
        first_time = 1;
    }

    if (!first_time) {
        return OK;
    }

    // Code to run only at the very first call.
    ap_log_error(APLOG_MARK, APLOG_NOTICE | APLOG_NOERRNO, 0, s,
                "ModSecurity: %s configured.", MSC_APACHE_CONNECTOR);

    return OK;
}


static void msc_register_hooks(apr_pool_t *pool)
{
    static const char *const postconfig_beforeme_list[] = {
        "mod_unique_id.c",
        "mod_ssl.c",
        NULL
    };

    static const char *const postconfig_afterme_list[] = {
        "mod_fcgid.c",
        "mod_cgid.c",
        NULL
    };

    ap_hook_pre_config(msc_hook_pre_config, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(msc_hook_post_config, postconfig_beforeme_list,
        postconfig_afterme_list, APR_HOOK_REALLY_LAST);

    /*
    ap_hook_handler(modsec_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_insert_filter(OutputFilter, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_register_output_filter("OUT", output_filter, NULL, AP_FTYPE_RESOURCE);
    ap_hook_insert_filter(InputFilter, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_register_input_filter("IN", input_filter, NULL, AP_FTYPE_RESOURCE);
    */
}


void *msc_hook_create_config_directory(apr_pool_t *mp, char *path)
{
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Created directory config for path: %s", path);

    return NULL;
}


static void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child)
{
    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "Merge parent %pp child %pp", parent, child);

    return NULL;
}


module AP_MODULE_DECLARE_DATA security3_module =
{
    STANDARD20_MODULE_STUFF,
    msc_hook_create_config_directory,  // Per-directory configuration.
    msc_hook_merge_config_directory,   // Merge handler for per-directory.
    NULL,                              // Per-server conf handler.
    NULL,                              // Merge handler for per-server
                                       // configurations.
    module_directives,
    msc_register_hooks
};
