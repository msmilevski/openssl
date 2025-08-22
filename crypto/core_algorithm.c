/*
 * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").  You may not
 * use this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "internal/provider.h"
#include "internal/core.h"

struct algorithm_data_st {
    OSSL_LIB_CTX *libctx;
    int operation_id;            /* May be zero for finding them all */
    int (*pre)(OSSL_PROVIDER *, int operation_id, void *data, int *result);
    void (*fn)(OSSL_PROVIDER *, const OSSL_ALGORITHM *, int no_store,
               void *data);
    int (*post)(OSSL_PROVIDER *, int operation_id, int no_store, void *data,
                int *result);
    void *data;
};

static int algorithm_do_this(OSSL_PROVIDER *provider, void *cbdata)
{
    struct algorithm_data_st *data = cbdata;
    int no_store = 0;    /* Assume caching is ok */
    int first_algorithm = 1;
    const OSSL_ALGORITHM *map = NULL;
    int ret = 0;

    /* Do we fulfill pre-conditions? */
    if (data->pre == NULL) {
        /* If there is no pre-condition function, assume "yes" */
        ret = 1;
    } else if (!data->pre(provider, data->operation_id, data->data, &ret)) {
        /* Error, bail out! */
        return 0;
    }

    /* If pre-condition not fulfilled, go to the next provider */
    if (!ret)
        return 1;

    map = ossl_provider_query_operation(provider, data->operation_id, &no_store);

    /* No algorithms available in this provider.  Go to the next one */
    if (map == NULL)
        goto post_process;

    for (; map->algorithm_names != NULL; map++) {
        const OSSL_ALGORITHM *thismap = map;

        if (data->fn != NULL)
            data->fn(provider, thismap, no_store, data->data);
        first_algorithm = 0;
    }

 post_process:
    /* Do we fulfill post-conditions? */
    if (data->post == NULL) {
        /* If there is no post-condition function, assume "yes" */
        ret = 1;
    } else if (!data->post(provider, data->operation_id, no_store, data->data,
                           &ret)) {
        /* Error, bail out! */
        return 0;
    }

    return ret;
}

void ossl_algorithm_do_all(OSSL_LIB_CTX *libctx, int operation_id,
                           OSSL_PROVIDER *provider,
                           int (*pre)(OSSL_PROVIDER *, int operation_id,
                                      void *data, int *result),
                           void (*fn)(OSSL_PROVIDER *provider,
                                      const OSSL_ALGORITHM *algo,
                                      int no_store, void *data),
                           int (*post)(OSSL_PROVIDER *, int operation_id,
                                       int no_store, void *data, int *result),
                           void *data)
{
    struct algorithm_data_st cbdata;
    
    /* Initialize cbdata efficiently */
    cbdata.libctx = libctx;
    cbdata.operation_id = operation_id;
    cbdata.pre = pre;
    cbdata.fn = fn;
    cbdata.post = post;
    cbdata.data = data;

    /* Handle specific provider case early */
    if (provider != NULL) {
        /* Use stack-allocated array directly instead of heap */
        OSSL_PROVIDER *single_provider = provider;
        ossl_provider_doall_activated(libctx, algorithm_do_this, &single_provider);
        return;
    }

    /* 
     * Only activate fallback default provider if we're traversing all providers
     * and libctx is not NULL
     */
    if (libctx != NULL) {
        ossl_provider_activate_fallback_default(libctx);
    }

    /* Traverse all providers */
    ossl_provider_doall_activated(libctx, algorithm_do_this, &cbdata);
}