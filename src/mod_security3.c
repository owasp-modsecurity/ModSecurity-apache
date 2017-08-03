
#include "mod_security3.h"
#include "msc_utils.h"

/*
 *
 */
msc_t *msc_apache;


int process_intervention (Transaction *t, request_rec *r)
{
    ModSecurityIntervention intervention;
    intervention.status = N_INTERVENTION_STATUS;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;

    int z = msc_intervention(t, &intervention);

    if (z == 0)
    {
        return N_INTERVENTION_STATUS;
    }

    if (intervention.log == NULL)
    {
        intervention.log = "(no log message was specified)";
    }

    if (intervention.status == 301 || intervention.status == 302
        ||intervention.status == 303 || intervention.status == 307)
    {
        if (intervention.url != NULL)
        {
            apr_table_setn(r->headers_out, "Location", intervention.url);
            return HTTP_MOVED_TEMPORARILY;
        }
    }

    if (intervention.status != N_INTERVENTION_STATUS)
    {
        return intervention.status;
    }

    return N_INTERVENTION_STATUS;
}


/**
 * Retrieves a previously stored transaction context by
 * looking at the main request, and the previous requests.
 */
static msc_t *retrieve_tx_context(request_rec *r) {
    msc_t *msr = NULL;
    request_rec *rx = NULL;

    /* Look in the current request first. */
    msr = (msc_t *)apr_table_get(r->notes, NOTE_MSR);
    if (msr != NULL)
    {
        msr->r = r;
        return msr;
    }

    /* If this is a subrequest then look in the main request. */
    if (r->main != NULL)
    {
        msr = (msc_t *)apr_table_get(r->main->notes, NOTE_MSR);
        if (msr != NULL)
        {
            msr->r = r;
            return msr;
        }
    }

    /* If the request was redirected then look in the previous requests. */
    rx = r->prev;
    while (rx != NULL)
    {
        msr = (msc_t *)apr_table_get(rx->notes, NOTE_MSR);
        if (msr != NULL)
        {
            msr->r = r;
            return msr;
        }
        rx = rx->prev;
    }

    return NULL;
}


/**
 * Stores transaction context where it can be found in subsequent
 * phases, redirections, or subrequests.
 */
static void store_tx_context(msc_t *msr, request_rec *r)
{
    apr_table_setn(r->notes, NOTE_MSR, (void *)msr);
}


static int hook_connection_early(conn_rec *conn)
{
    // At this point there isn't a request_rec attached to the request,
    // therefore we can't create the config yet, lets wait till next phase.

    return DECLINED;
}


static int process_request_headers(request_rec *r, msc_t *msr) {
    /* process uri */
    {
        int it;
        msc_process_uri(msr->t, r->unparsed_uri, r->method, r->protocol);

        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            return it;
        }
    }

    /* add request headers */
    {
        const apr_array_header_t *arr = NULL;
        const apr_table_entry_t *te = NULL;
        int i;
        int it;

        arr = apr_table_elts(r->headers_in);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++)
        {
            const char *key = te[i].key;
            const char *val = te[i].val;
            msc_add_request_header(msr->t, key, val);
        }
        msc_process_request_headers(msr->t);

        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            return it;
        }
    }

    return N_INTERVENTION_STATUS;
}


/**
 * Initial request processing, executed immediatelly after
 * Apache receives the request headers. This function wil create
 * a transaction context.
 */
static int hook_request_early(request_rec *r) {
    msc_t *msr = NULL;
    int rc = DECLINED;
    int it = 0;
    FILE *debug = NULL;

    msc_conf_t *cnf = ap_get_module_config(r->per_dir_config,
                            &security3_module);

    /* This function needs to run only once per transaction
     * (i.e. subrequests and redirects are excluded).
     */
    if ((r->main != NULL) || (r->prev != NULL) || cnf == NULL)
    {
        return DECLINED;
    }

    /* Initialise transaction context and
     * create the initial configuration.
     */
    msr = apr_palloc(r->pool, sizeof(msc_t));
    msr->t = msc_new_transaction(msc_apache->modsec, cnf->rules_set, NULL);
    if (msr == NULL)
    {
        return DECLINED;
    }
    store_tx_context(msr, r);

    msc_process_connection(msr->t, r->connection->client_ip,
        r->connection->client_addr->port,
        r->server->server_hostname,
        (int) r->server->port);

    it = process_intervention(msr->t, r);
    if (it != N_INTERVENTION_STATUS)
    {
        return it;
    }

#ifdef REQUEST_EARLY
    it = process_request_headers(r, msr);
    if (it != N_INTERVENTION_STATUS)
    {
        return it;
    }
#endif

    return rc;
}

/**
 * Invoked as the first hook in the handler chain, this function
 * executes the second phase of ModSecurity request processing.
 */
static int hook_request_late(request_rec *r)
{
    msc_t *msr = NULL;
    int it;

    /* This function needs to run only once per transaction
     * (i.e. subrequests and redirects are excluded).
     */
    if ((r->main != NULL) || (r->prev != NULL))
    {
        return DECLINED;
    }

    /* Find the transaction context and make sure
     * we are supposed to proceed.
     */
    msr = retrieve_tx_context(r);
    if (msr == NULL)
    {
        /* If we can't find the context that probably means it's
         * a subrequest that was not initiated from the outside.
         */
        return DECLINED;
    }

#ifndef REQUEST_EARLY
    it = process_request_headers(r, msr);
    if (it != N_INTERVENTION_STATUS)
    {
        return it;
    }
#endif

    msc_process_request_body(msr->t);
    it = process_intervention(msr->t, r);
    if (it != N_INTERVENTION_STATUS)
    {
        return it;
    }

    return DECLINED;
}


/**
 * Invoked at the end of each transaction.
 */
static int hook_log_transaction(request_rec *r)
{
    const apr_array_header_t *arr = NULL;
    request_rec *origr = NULL;
    msc_t *msr = NULL;
    int it;

    msr = retrieve_tx_context(r);
    if (msr == NULL)
    {
        return DECLINED;
    }

    msc_process_logging(msr->t);
    it = process_intervention(msr->t, r);
    if (it != N_INTERVENTION_STATUS)
    {
        return it;
    }
}


/*
 * Called only once. Used to initialise the ModSecurity
 *
 */
int msc_apache_init(apr_pool_t *mp)
{
    msc_apache = apr_palloc(mp, sizeof(msc_t));
    if (msc_apache == NULL)
    {
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


/*
 * Used to cleanup the module
 *
 */
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
    if (data == NULL)
    {
        apr_pool_userdata_set((const void *) 1, key,
                apr_pool_cleanup_null, mp);
        first_time = 1;
    }

    if (!first_time)
    {
        return OK;
    }

    // Code to run only at the very first call.
    int ret = msc_apache_init(mp);

    if (ret == -1)
    {
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
    if (data == NULL)
    {
        apr_pool_userdata_set((const void *) 1, key,
            apr_pool_cleanup_null, s->process->pool);
        first_time = 1;
    }

    if (!first_time)
    {
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

    static const char *const postread_beforeme_list[] = {
        "mod_rpaf.c",
        "mod_rpaf-2.0.c",
        "mod_extract_forwarded.c",
        "mod_extract_forwarded2.c",
        "mod_remoteip.c",
        "mod_custom_header.c",
        "mod_breach_realip.c",
        "mod_breach_trans.c",
        "mod_unique_id.c",
        NULL
    };

    static const char *const postread_afterme_list[] = {
        "mod_log_forensic.c",
        NULL
    };

    static const char *const transaction_afterme_list[] = {
        "mod_log_config.c",
        NULL
    };

    static const char *const fixups_beforeme_list[] = {
        "mod_env.c",
        NULL
    };

    ap_hook_pre_config(msc_hook_pre_config, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_post_config(msc_hook_post_config, postconfig_beforeme_list,
        postconfig_afterme_list, APR_HOOK_REALLY_LAST);

    /* Connection processing hooks */
    ap_hook_process_connection(hook_connection_early, NULL, NULL, APR_HOOK_FIRST);

    /* Transaction processing hooks */
    ap_hook_post_read_request(hook_request_early,
        postread_beforeme_list, postread_afterme_list, APR_HOOK_REALLY_FIRST);

    ap_hook_fixups(hook_request_late, fixups_beforeme_list, NULL, APR_HOOK_REALLY_FIRST);


    ap_hook_insert_filter(hook_insert_filter, NULL, NULL, APR_HOOK_FIRST);

    /* Logging */
    /* ap_hook_error_log is called for every error log entry that apache writes.
     * may not be necessary in our particular case. Disabling for now.
     *
     * ap_hook_error_log(hook_error_log, NULL, NULL, APR_HOOK_MIDDLE);
     *
     */

    ap_hook_log_transaction(hook_log_transaction, NULL, transaction_afterme_list, APR_HOOK_MIDDLE);

    ap_register_input_filter("MODSECURITY_IN", input_filter,
        NULL, AP_FTYPE_CONTENT_SET);

    ap_register_output_filter("MODSECURITY_OUT", output_filter,
        NULL, AP_FTYPE_CONTENT_SET - 3);

}


/**
 * Invoked right before request processing begins. This is
 * when we need to decide if we want to hook into the output
 * filter chain.
 */
static void hook_insert_filter(request_rec *r)
{
    msc_t *msr = NULL;

    /* Find the transaction context first. */
    msr = retrieve_tx_context(r);
    if (msr == NULL)
    {
        return;
    }

#if 1
    /* Add the input filter, but only if we need it to run. */
    ap_add_input_filter("MODSECURITY_IN", msr, r, r->connection);
#endif

    /* The output filters only need to be added only once per transaction
     * (i.e. subrequests and redirects are excluded).
     */
    if ((r->main != NULL) || (r->prev != NULL))
    {
        return;
    }


    ap_add_output_filter("MODSECURITY_OUT", msr, r, r->connection);
}


void *msc_hook_create_config_directory(apr_pool_t *mp, char *path)
{
    msc_conf_t *cnf = NULL;

    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Created directory config for path: %s", path);

    cnf = apr_palloc(mp, sizeof(msc_conf_t));
    memset(cnf, '\0', sizeof(msc_conf_t));
    if (cnf == NULL)
    {
        goto end;
    }

    cnf->rules_set = msc_create_rules_set();
    if (path != NULL)
    {
        cnf->name_for_debug = strdup(path);
    }

    ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
        "ModSecurity: Config for path: %s is at: %pp", path, cnf);

end:
    return cnf;
}


static void *msc_hook_merge_config_directory(apr_pool_t *mp, void *parent,
    void *child)
{
    msc_conf_t *cnf_p = parent;
    msc_conf_t *cnf_c = child;
    msc_conf_t *cnf_new = msc_hook_create_config_directory(mp, cnf_c->name_for_debug);

    if (cnf_p && cnf_c)
    {
        const char *error = NULL;
        int ret;
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child %pp [%s]", cnf_p,
            cnf_p->name_for_debug,
            child, cnf_c->name_for_debug);

        ret = msc_rules_merge(cnf_new->rules_set, cnf_c->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Merge failed - > %s", error);
            return NULL;
        }

        ret = msc_rules_merge(cnf_new->rules_set, cnf_p->rules_set, &error);
        if (ret < 0)
        {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Merge failed - > %s", error);
            return NULL;
        }

        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
                "ModSecurity: Merge OK");
    }
    if (cnf_c && !cnf_p)
    {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent -NULL- [-NULL-] child %pp [%s]",
            cnf_c, cnf_c->name_for_debug);
    }
    else if (cnf_p && !cnf_c)
    {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP|APLOG_NOERRNO, 0, mp,
            "ModSecurity: Merge parent %pp [%s] child -NULL- [-NULL-]",
            cnf_p, cnf_p->name_for_debug);
    }

    return cnf_new;
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

