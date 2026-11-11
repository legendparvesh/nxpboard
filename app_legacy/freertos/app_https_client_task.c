/*
 * Copyright 2023-2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * FOCAL hackathon - LEGACY firmware, benchmark wrapper.
 *
 * This is the original challenge code (one TLS 1.2 ECDHE-RSA connection + GET,
 * DRBG seeded from the TRNG on every connection) with exactly one change: the
 * connect + handshake + GET round is repeated `iterations` times and timed with
 * the RTOS tick, and min / median / avg / max are printed at the end. Rounds
 * after the first run quiet (no certificate dump) so UART output does not sit
 * inside the timed window. Nothing in the TLS path is changed.
 */

#include <stdbool.h>
#include <string.h>
#include <assert.h>

/* FreeRTOS */
#include "FreeRTOS.h"
#include "task.h"

/* App */
#include "app_https_client_task.h"
#include "app_corehttp.h"
#include "app_mbedtls_socket.h"

static void client_task(void *args);

void app_https_client_task_init(https_client_task_context_t *context,
                                const configSTACK_DEPTH_TYPE stack_depth,
                                UBaseType_t priority)
{
    https_client_task_context_t *args;
    BaseType_t result;

    args = (https_client_task_context_t *)pvPortMalloc(sizeof(https_client_task_context_t));
    if (args == NULL)
    {
        PRINTF("Failed to allocate client_task context.\r\n");
        return;
    }

    memcpy(args, context, sizeof(https_client_task_context_t));

    result = xTaskCreate(client_task, "client_task", stack_depth, args, priority, NULL);
    if (result != pdTRUE)
    {
        vPortFree(args);
        PRINTF("client_task creation failed");
    }
}

/* One round exactly as the original client_task did it. Returns 0 on HTTP 200. */
static int one_round(https_client_task_context_t *context, bool verbose)
{
    TransportInterface_t xport_interface = {
        .send            = app_corehttp_send,
        .recv            = app_corehttp_recv,
        .writev          = NULL,
        .pNetworkContext = NULL,
    };
    int rc = -1;

    /* Create context for underlying transport (TCP connect + TLS handshake) */

    NetworkContext_t *nwk_ctx = app_corehttp_create_context(context->host, context->port);
    if (nwk_ctx == NULL)
    {
        return -1;
    }

    HTTPStatus_t status;

    /* Build request headers */

    HTTPRequestHeaders_t req_headers;
    HTTPRequestInfo_t req_info;

    memset(&req_headers, 0x00, sizeof(req_headers));
    memset(&req_info, 0x00, sizeof(req_info));

    req_headers.pBuffer   = pvPortMalloc(context->max_request_len);
    req_headers.bufferLen = context->max_request_len;

    if (req_headers.pBuffer == NULL)
    {
        PRINTF("Failed to allocate header buffer.\r\n");

        goto destroy_ctx_exit;
    }

    req_info.pMethod   = HTTP_METHOD_GET;
    req_info.methodLen = sizeof(HTTP_METHOD_GET) - 1;
    req_info.pPath     = context->path;
    req_info.pathLen   = strlen(context->path);
    req_info.pHost     = context->host;
    req_info.hostLen   = strlen(context->host);
    req_info.reqFlags  = HTTP_REQUEST_KEEP_ALIVE_FLAG;

    status = HTTPClient_InitializeRequestHeaders(&req_headers, &req_info);
    if (status != HTTPSuccess)
    {
        PRINTF("Failed to build request headers.\r\n");

        goto free_hdr_exit;
    }

    /* Initialize transport interface */

    xport_interface.pNetworkContext = nwk_ctx;

    HTTPResponse_t resp;

    memset(&resp, 0x00, sizeof(resp));

    resp.pBuffer   = pvPortMalloc(context->max_response_len);
    resp.bufferLen = context->max_response_len;

    if (resp.pBuffer == NULL)
    {
        PRINTF("Failed to allocate response buffer.\r\n");

        goto free_hdr_exit;
    }

    if (verbose) PRINTF("GET %s\r\n", context->path);
    status = HTTPClient_Send(&xport_interface, &req_headers, NULL, 0, &resp, 0);
    if (status != HTTPSuccess)
    {
        PRINTF("HTTP request encountered error: %d\r\n", status);

        goto free_resp_exit;
    }

    if (verbose)
    {
        PRINTF("Response code: %d\r\n", resp.statusCode);
        PRINTF("Response body:\r\n");

        for (uint32_t i = 0; i < resp.bodyLen; i++)
        {
            if (resp.pBody[i] == '\n')
            {
                PRINTF("\r");
            }
            PRINTF("%c", resp.pBody[i]);
        }

        PRINTF("\r\n");
    }
    rc = (resp.statusCode == 200) ? 0 : -2;

free_resp_exit:
    vPortFree(resp.pBuffer);

free_hdr_exit:
    vPortFree(req_headers.pBuffer);

destroy_ctx_exit:
    app_corehttp_destroy_context(nwk_ctx);

    return rc;
}

static void sort_u32(uint32_t *v, uint32_t n)
{
    for (uint32_t i = 1; i < n; i++)
    {
        uint32_t x = v[i];
        uint32_t j = i;
        while (j > 0 && v[j - 1] > x)
        {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = x;
    }
}

static void print_stat_line(const char *label, uint32_t *samples, uint32_t n)
{
    if (n == 0) return;
    uint64_t sum = 0;
    for (uint32_t i = 0; i < n; i++) sum += samples[i];
    sort_u32(samples, n);
    const uint32_t median = (n & 1U) ? samples[n / 2] : (samples[n / 2 - 1] + samples[n / 2]) / 2U;
    PRINTF("%-14s: %4lu   %4lu   %4lu   %4lu\r\n", label, (unsigned long)samples[0], (unsigned long)median,
           (unsigned long)(sum / n), (unsigned long)samples[n - 1]);
}

static void client_task(void *args)
{
    https_client_task_context_t *context = (https_client_task_context_t *)args;

    assert(context != NULL);
    assert(context->host != NULL);
    assert(context->path != NULL);
    assert(context->port != 0U);
    assert(context->max_request_len > 0U);
    assert(context->max_response_len > 0U);

    const uint32_t n = context->iterations > 0U ? context->iterations : 1U;
    uint32_t *round_ms     = pvPortMalloc(n * sizeof(uint32_t));
    uint32_t *handshake_ms = pvPortMalloc(n * sizeof(uint32_t));
    uint32_t ok = 0, failed = 0;

    if (round_ms == NULL || handshake_ms == NULL)
    {
        PRINTF("Failed to allocate benchmark buffers.\r\n");
        goto task_end;
    }

    PRINTF("\r\n=== LEGACY firmware benchmark: %lu rounds of TCP connect + TLS 1.2 handshake + GET %s ===\r\n",
           (unsigned long)n, context->path);

    for (uint32_t i = 0; i < n; i++)
    {
        const bool verbose = (i == 0);
        app_mbedtls_socket_quiet = !verbose;

        const TickType_t t0 = xTaskGetTickCount();
        const int rc        = one_round(context, verbose);
        const uint32_t ms   = (uint32_t)(xTaskGetTickCount() - t0) * (uint32_t)portTICK_PERIOD_MS;

        if (rc == 0)
        {
            round_ms[ok]     = ms;
            handshake_ms[ok] = app_mbedtls_socket_last_handshake_ms;
            ok++;
            PRINTF("[%3lu/%3lu] handshake %4lu ms | round %4lu ms | HTTP 200\r\n", (unsigned long)(i + 1),
                   (unsigned long)n, (unsigned long)app_mbedtls_socket_last_handshake_ms, (unsigned long)ms);
        }
        else
        {
            failed++;
            PRINTF("[%3lu/%3lu] round failed (rc=%d)\r\n", (unsigned long)(i + 1), (unsigned long)n, rc);
        }
    }

    PRINTF("\r\n=== LEGACY benchmark summary: %lu ok, %lu failed ===\r\n", (unsigned long)ok, (unsigned long)failed);
    PRINTF("                  min   median   avg    max  (ms)\r\n");
    print_stat_line("TLS handshake ", handshake_ms, ok);
    print_stat_line("Full round    ", round_ms, ok);
    PRINTF("(round = TCP connect + entropy/DRBG seed + TLS 1.2 handshake + HTTP GET, as the original code runs it)\r\n");
    PRINTF("=== Done ===\r\n");

task_end:
    vPortFree(handshake_ms);
    vPortFree(round_ms);
    vPortFree(context);
    vTaskDelete(NULL);
}
