
#include "msc_utils.h"


int id(const char *fn, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    FILE *f = fopen(fn, "a"); 
    vfprintf(f, format, args);
    fclose(f);
    va_end(args);
}


/**
 * Sends a brigade with an error bucket down the filter chain.
 */
apr_status_t send_error_bucket(msc_t *msr, ap_filter_t *f, int status)
{
    apr_bucket_brigade *brigade = NULL;
    apr_bucket *bucket = NULL;

    /* Set the status line explicitly for the error document */
    f->r->status_line = ap_get_status_line(status);

    brigade = apr_brigade_create(f->r->pool, f->r->connection->bucket_alloc);
    if (brigade == NULL)
    {
        return APR_EGENERAL;
    }

    bucket = ap_bucket_error_create(status, NULL, f->r->pool,
        f->r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        return APR_EGENERAL;
    }

    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    bucket = apr_bucket_eos_create(f->r->connection->bucket_alloc);
    if (bucket == NULL)
    {
        return APR_EGENERAL;
    }

    APR_BRIGADE_INSERT_TAIL(brigade, bucket);

    ap_pass_brigade(f->next, brigade);

    /* NOTE:
     * It may not matter what we do from the filter as it may be too
     * late to even generate an error (already sent to client).  Nick Kew
     * recommends to return APR_EGENERAL in hopes that the handler in control
     * will notice and do The Right Thing.  So, that is what we do now.
     */
    return APR_EGENERAL;
}

