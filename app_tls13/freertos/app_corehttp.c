/*
 * Copyright 2023-2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* FreeRTOS */
#include "FreeRTOS.h"
#include "task.h"

/* App */
#include "app_corehttp.h"
#include "app_mbedtls_socket.h"

/* Debug Console */
#include "fsl_debug_console.h"

typedef struct
{
    app_mbedtls_socket_t tls;
} app_corehttp_ctx_t;

NetworkContext_t *app_corehttp_create_context(char *host, uint16_t port, int tls_version, bool verbose)
{
    app_corehttp_ctx_t *ctx = pvPortMalloc(sizeof(app_corehttp_ctx_t));
    if (ctx == NULL)
    {
        PRINTF("NetworkCtx: Failed to allocate context.\r\n");
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->tls.verbose     = verbose;
    ctx->tls.tls_version = tls_version;

    int ret = app_mbedtls_socket_connect(&ctx->tls, host, port);
    if (ret != 0)
    {
        PRINTF("NetworkCtx: Failed to establish TLS connection to %s:%d, ret=%d.\r\n", host, port, ret);
        goto free_exit;
    }

    if (verbose)
    {
        PRINTF("NetworkCtx: Connection established.\r\n");
    }

    return (NetworkContext_t *)ctx;

free_exit:
    vPortFree(ctx);
    return NULL;
}

void app_corehttp_destroy_context(NetworkContext_t *ctx)
{
    app_corehttp_ctx_t *c = (app_corehttp_ctx_t *)ctx;

    app_mbedtls_socket_close(&c->tls);
    if (c->tls.verbose)
    {
        PRINTF("NetworkCtx: Connection closed.\r\n");
    }

    vPortFree(c);
}

void app_corehttp_get_stats(NetworkContext_t *ctx, app_corehttp_stats_t *stats)
{
    app_corehttp_ctx_t *c = (app_corehttp_ctx_t *)ctx;

    stats->tcp_connect_ms = c->tls.tcp_connect_ms;
    stats->handshake_ms   = c->tls.handshake_ms;
    stats->handshake_tx = c->tls.handshake_tx;
    stats->handshake_rx = c->tls.handshake_rx;
    stats->total_tx     = c->tls.total_tx;
    stats->total_rx     = c->tls.total_rx;
}

int32_t app_corehttp_send(NetworkContext_t *ctx, const void *buf, size_t size)
{
    app_corehttp_ctx_t *c = (app_corehttp_ctx_t *)ctx;

    return app_mbedtls_socket_send(&c->tls, (uint8_t *)buf, size);
}

int32_t app_corehttp_recv(NetworkContext_t *ctx, void *buf, size_t size)
{
    app_corehttp_ctx_t *c = (app_corehttp_ctx_t *)ctx;

    return app_mbedtls_socket_recv(&c->tls, (uint8_t *)buf, size);
}
