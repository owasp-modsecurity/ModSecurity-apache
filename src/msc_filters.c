
#include "msc_filters.h"
#include "msc_utils.h"


apr_status_t input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t nbytes)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;

    apr_bucket_brigade *pbbTmp;
    int ret;

    msc_t *msr = (msc_t *)f->ctx;

    /* Do we have the context? */
    if (msr == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, f->r->server,
                "ModSecurity: Internal Error: msr is null in input filter.");
        ap_remove_output_filter(f);
        return send_error_bucket(msr, f, HTTP_INTERNAL_SERVER_ERROR);
    }

    pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);
    if (APR_BRIGADE_EMPTY(pbbTmp))
    {
        ret = ap_get_brigade(f->next, pbbTmp, mode, block, nbytes);

        if (mode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
            return ret;
    }

    while (!APR_BRIGADE_EMPTY(pbbTmp))
    {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pbbTmp);
        apr_bucket *pbktOut;
        const char *data;
        apr_size_t len;
        apr_size_t n;
        int it;

        if (APR_BUCKET_IS_EOS(pbktIn))
        {
            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            break;
        }

        ret=apr_bucket_read(pbktIn, &data, &len, block);
        if (ret != APR_SUCCESS)
        {
            return ret;
        }

        msc_append_request_body(msr->t, data, len);
        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            ap_remove_output_filter(f);
            return send_error_bucket(msr, f, it);
        }

        // FIXME: Now we should have the body. Is this sane?
        msc_process_request_body(msr->t);

        pbktOut = apr_bucket_heap_create(data, len, 0, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
        apr_bucket_delete(pbktIn);
    }
    return APR_SUCCESS;
}


apr_status_t output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)
{
    request_rec *r = f->r;
    msc_t *msr = (msc_t *)f->ctx;

    /* Do we have the context? */
    if (msr == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, f->r->server,
                "ModSecurity: Internal Error: msr is null in output filter.");
        ap_remove_output_filter(f);
        return send_error_bucket(msr, f, HTTP_INTERNAL_SERVER_ERROR);
    }

    /* response headers */
    {
        const apr_array_header_t *arr = NULL;
        const apr_table_entry_t *te = NULL;
        int i, it;

        arr = apr_table_elts(r->err_headers_out);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++)
        {
            const char *key = te[i].key;
            const char *val = te[i].val;
            msc_add_response_header(msr->t, key, val);
        }

        arr = apr_table_elts(r->headers_out);
        te = (apr_table_entry_t *)arr->elts;
        for (i = 0; i < arr->nelts; i++)
        {
            const char *key = te[i].key;
            const char *val = te[i].val;
            msc_add_response_header(msr->t, key, val);
        }

        msc_process_response_headers(msr->t, r->status, "HTTP 1.1");

        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            ap_remove_output_filter(f);
            return send_error_bucket(msr, f, it);
        }
    }

    /* response body */
    {
        apr_bucket *pbktIn;
        int it;

        for (pbktIn = APR_BRIGADE_FIRST(bb_in);
            pbktIn != APR_BRIGADE_SENTINEL(bb_in);
            pbktIn = APR_BUCKET_NEXT(pbktIn))
        {
            const char *data;
            apr_size_t len;
            apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);
            msc_append_response_body(msr->t, data, len);
        }
        msc_process_response_body(msr->t);

        it = process_intervention(msr->t, r);
        if (it != N_INTERVENTION_STATUS)
        {
            ap_remove_output_filter(f);
            return send_error_bucket(msr, f, it);
        }
    }

    return ap_pass_brigade(f->next, bb_in);
}

