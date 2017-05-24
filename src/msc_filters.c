
#include "apache_http_modsecurity.h"
#include "msc_filters.h"

static void OutputFilter(request_rec *r)
{
    FilterConfig *pConfig = ap_get_module_config(r->server->module_config,
                            &security3_module);

    if (!pConfig->oEnabled)
    {
        return;
    }

    ap_add_output_filter("OUT", NULL, r, r->connection);
}

static void InputFilter(request_rec *r)
{
    FilterConfig *pConfig = ap_get_module_config(r->server->module_config,
                            &security3_module);
    if (!pConfig->iEnabled)
    {
        return;
    }

    ap_add_input_filter("IN", NULL, r, r->connection);
}

static int modsec_handler(request_rec *r)
{


    if (!r->handler || strcmp(r->handler, "security3_module"))
    {
        return (DECLINED);
    }

    ap_rputs("Welcome to ModSec!<br/>", r);
    fprintf(stderr, "Welcome to ModSec!\n");
    return OK;
}



static void *FilterOutCreateServerConfig(apr_pool_t *p, server_rec *s)
{
    FilterConfig *pConfig = apr_pcalloc(p,sizeof *pConfig);

    pConfig->oEnabled = 1;

    return pConfig;
}

static void *FilterInCreateServerConfig(apr_pool_t *p, server_rec *s)
{
    FilterConfig *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->iEnabled = 1;

    return pConfig;
}

static int input_filter(ap_filter_t *f, apr_bucket_brigade *pbbOut,
                        ap_input_mode_t eMode, apr_read_type_e eBlock, apr_off_t nBytes)
{

    request_rec *r = f->r;
    conn_rec *c = r->connection;
    FilterContext *pCtx;
    apr_status_t ret;

    apache_http_modsecurity_main_conf_t *md = ap_get_module_config(r->server->module_config,
            &security3_module);
    apache_http_modsecurity_loc_conf_t *cf = ap_get_module_config(r->server->module_config,
            &security3_module);

    md->transaction = msc_new_transaction(md->modsec, cf->rules_set, NULL);

    if (!(pCtx = f->ctx))
    {
        f->ctx = pCtx = apr_palloc(r->pool, sizeof *pCtx);
        pCtx->pbbTmp = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    if (APR_BRIGADE_EMPTY(pCtx->pbbTmp))
    {
        ret = ap_get_brigade(f->next, pCtx->pbbTmp, eMode, eBlock, nBytes);

        if (eMode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
            return ret;
    }

    while (!APR_BRIGADE_EMPTY(pCtx->pbbTmp))
    {
        apr_bucket *pbktIn = APR_BRIGADE_FIRST(pCtx->pbbTmp);
        apr_bucket *pbktOut;
        const char *data;
        apr_size_t len;
        unsigned char *buf;
        apr_size_t n;

        if (APR_BUCKET_IS_EOS(pbktIn))
        {
            APR_BUCKET_REMOVE(pbktIn);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktIn);
            break;
        }

        ret=apr_bucket_read(pbktIn, &data, &len, eBlock);
        if (ret != APR_SUCCESS)
        {
            return ret;
        }

        buf = (unsigned char *) malloc(len);
        for (n=0 ; n < len ; ++n)
        {
            buf[n] = data[n];
        }

        msc_append_request_body(md->transaction, buf, len);
        fprintf(stderr, "req app\n");


        pbktOut = apr_bucket_heap_create(buf, len, 0, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
        apr_bucket_delete(pbktIn);
    }
    msc_process_request_body(md->transaction);
    msc_process_logging(md->transaction);
    fprintf(stderr, "req \n");


    return APR_SUCCESS;
}

static int output_filter(ap_filter_t *f, apr_bucket_brigade *pbbIn)
{

    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;

    pbbOut = apr_brigade_create(r->pool, c->bucket_alloc);


    apache_http_modsecurity_main_conf_t *md = ap_get_module_config(r->server->module_config,
            &security3_module);
    apache_http_modsecurity_loc_conf_t *cf = ap_get_module_config(r->server->module_config,
            &security3_module);

    md->transaction = msc_new_transaction(md->modsec, cf->rules_set, NULL);

    for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
            pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
            pbktIn = APR_BUCKET_NEXT(pbktIn))
    {
        const char *data;
        apr_size_t len;
        unsigned char *buf;
        apr_size_t n;
        apr_bucket *pbktOut;

        if (APR_BUCKET_IS_EOS(pbktIn))
        {
            apr_bucket *pbktEOS = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pbbOut, pbktEOS);
            continue;
        }

        apr_bucket_read(pbktIn, &data, &len, APR_BLOCK_READ);

        buf = apr_bucket_alloc(len, c->bucket_alloc);
        for (n=0 ; n < len ; ++n)
        {
            buf[n] = data[n];
        }

        msc_append_response_body(md->transaction, buf, len);
        fprintf(stderr, "res app\n");

        pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut, pbktOut);
    }
    msc_process_response_body(md->transaction);
    msc_process_logging(md->transaction);
    fprintf(stderr, "res \n");
    fprintf(stderr, "WMI '%s' \n",msc_who_am_i (md->modsec	));


    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next, pbbOut);
}
