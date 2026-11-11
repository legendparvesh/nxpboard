/*
 * Copyright 2023-2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * FOCAL hackathon benchmark task: runs N rounds of
 *   TCP connect + TLS handshake [+ hybrid authentication] + HTTP GET
 * against the challenge server, interleaving several "arms" (TLS version /
 * key-exchange / authentication configurations) so that every arm experiences
 * the same network conditions, and prints min / median / avg / max per phase
 * and per arm.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* FreeRTOS */
#include "FreeRTOS.h"
#include "task.h"

/* App */
#include "app_https_client_task.h"
#include "app_corehttp.h"
#include "app_mbedtls_socket.h"
#include "app_pqc_bench.h"
#include "app_hybrid_auth.h"

#ifndef APP_PQC_BENCH
/* 1 = run the crypto micro-benchmarks once before the TLS rounds. */
#define APP_PQC_BENCH 1
#endif

/* One benchmark arm = one TLS configuration. */
typedef struct
{
    const char *label; /* printed per round and in the summary */
    int tls_version;   /* 2 or 3 */
    int hybrid_kex;    /* 1 = offer X25519MLKEM768 first */
    int hybrid_auth;   /* 1 = sign the TLS exporter with ML-DSA + ECDSA, self-verify, send it;
                        * 2 = sign and send only (deployment mode: the peer verifies) */
} bench_arm_t;

#define MAX_ARMS 5

/* Label for the TLS exporter the device signs (any fixed ASCII string works;
 * both ends must agree if the server ever verifies). */
#define AUTH_EXPORTER_LABEL "EXPORTER-focal-hybrid-auth"
#define AUTH_HEADER_NAME    "X-Hybrid-Auth"

static void client_task(void *args);
static void sort_u32(uint32_t *v, uint32_t n);
static void print_stat_line(const char *label, uint32_t *samples, uint32_t n);
static void print_stat_line_for(const char *label, const uint32_t *samples, const uint8_t *arm_of, uint32_t n,
                                uint8_t want, uint32_t *scratch);
static uint32_t build_arms(uint32_t tls_mode, bench_arm_t *arms);

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

/* Translate tls_mode (see app_https_client_task.h) into a list of arms. */
static uint32_t build_arms(uint32_t tls_mode, bench_arm_t *arms)
{
    const bench_arm_t tls12  = {"TLS1.2         ", 2, 0, 0};
    const bench_arm_t tls13  = {"TLS1.3         ", 3, 0, 0};
    const bench_arm_t hybrid = {"TLS1.3+MLKEM   ", 3, 1, 0};
    const bench_arm_t auth   = {"MLKEM+MLDSAauth", 3, 1, 1};
    const bench_arm_t authso = {"MLKEM+MLDSAsign", 3, 1, 2}; /* sign only, no self-verify */
    uint32_t n = 0;

    switch (tls_mode)
    {
        case 2: arms[n++] = tls12; break;
        case 3: arms[n++] = tls13; break;
        case 4: arms[n++] = hybrid; arms[n++] = tls13; break;
        case 5: arms[n++] = hybrid; break;
        case 6: arms[n++] = hybrid; arms[n++] = tls13; arms[n++] = tls12; break;
        case 7: arms[n++] = auth; arms[n++] = hybrid; arms[n++] = tls13; arms[n++] = tls12; break;
        case 8: arms[n++] = auth; break;
        case 9: arms[n++] = authso; arms[n++] = auth; arms[n++] = hybrid; arms[n++] = tls13; arms[n++] = tls12; break;
        case 0:
        default: arms[n++] = tls13; arms[n++] = tls12; break;
    }
    return n;
}

static void client_task(void *args)
{
    https_client_task_context_t *context = (https_client_task_context_t *)args;
    TransportInterface_t xport_interface = {
        .send            = app_corehttp_send,
        .recv            = app_corehttp_recv,
        .writev          = NULL,
        .pNetworkContext = NULL,
    };

    assert(context != NULL);
    assert(context->host != NULL);
    assert(context->path != NULL);
    assert(context->port != 0U);
    assert(context->max_request_len > 0U);
    assert(context->max_response_len > 0U);

    const uint32_t iterations = (context->iterations == 0U) ? 1U : context->iterations;

#if APP_PQC_BENCH
    app_pqc_bench_run();
#endif
    const bool auth_ready = (app_hybrid_auth_init() == 0);
#if APP_PQC_BENCH
    app_hybrid_auth_bench();
#endif

    bench_arm_t arms[MAX_ARMS];
    const uint32_t n_arms = build_arms(context->tls_mode, arms);

    /* Buffers are allocated once and reused for every round. */
    uint8_t *hdr_buf  = pvPortMalloc(context->max_request_len);
    uint8_t *resp_buf = pvPortMalloc(context->max_response_len);
    char *auth_hdr    = pvPortMalloc(5120); /* base64(3309 B) + base64(64 B) + labels */

    /* Per-round samples (for median), which arm each sample belongs to, and a scratch buffer. */
    uint32_t *setup_ms_s = pvPortMalloc(iterations * sizeof(uint32_t));
    uint32_t *tcp_ms     = pvPortMalloc(iterations * sizeof(uint32_t));
    uint32_t *hs_ms      = pvPortMalloc(iterations * sizeof(uint32_t));
    uint32_t *auth_ms    = pvPortMalloc(iterations * sizeof(uint32_t)); /* sign + self-verify, both algorithms */
    uint32_t *http_ms    = pvPortMalloc(iterations * sizeof(uint32_t));
    uint32_t *tot_ms     = pvPortMalloc(iterations * sizeof(uint32_t));
    uint32_t *scratch    = pvPortMalloc(iterations * sizeof(uint32_t));
    uint8_t *arm_of      = pvPortMalloc(iterations * sizeof(uint8_t));

    if (hdr_buf == NULL || resp_buf == NULL || auth_hdr == NULL || setup_ms_s == NULL || tcp_ms == NULL ||
        hs_ms == NULL || auth_ms == NULL || http_ms == NULL || tot_ms == NULL || scratch == NULL || arm_of == NULL)
    {
        PRINTF("Failed to allocate benchmark buffers.\r\n");
        goto free_exit; /* vPortFree(NULL) is a no-op */
    }

    uint32_t ok_rounds = 0, fail_rounds = 0;
    uint32_t hs_tx_sum[MAX_ARMS] = {0}, hs_rx_sum[MAX_ARMS] = {0}, tx_sum[MAX_ARMS] = {0}, rx_sum[MAX_ARMS] = {0};
    uint32_t arm_ok[MAX_ARMS] = {0}, arm_fail[MAX_ARMS] = {0};
    /* Authentication sub-timings (µs) accumulated per arm for the summary. */
    uint64_t mldsa_sign_us[MAX_ARMS] = {0}, mldsa_verify_us[MAX_ARMS] = {0}, ecdsa_sign_us[MAX_ARMS] = {0},
             ecdsa_verify_us[MAX_ARMS] = {0};
    uint32_t auth_fail[MAX_ARMS] = {0};

    PRINTF("\r\n=== Benchmark: %lu rounds of TCP connect + TLS handshake [+ auth] + GET %s ===\r\n",
           (unsigned long)iterations, context->path);
    PRINTF("=== %lu arm(s), interleaved round by round:", (unsigned long)n_arms);
    for (uint32_t a = 0; a < n_arms; a++)
    {
        PRINTF(" [%s]", arms[a].label);
    }
    PRINTF(" ===\r\n");

    for (uint32_t round = 1; round <= iterations; round++)
    {
        const uint32_t arm_idx = (round - 1U) % n_arms;
        const bench_arm_t *arm = &arms[arm_idx];

        /* Full protocol/cipher/certificate dump on the first round of each arm. */
        const bool verbose = (round <= n_arms);

        /* Round timer: TCP connect + TLS handshake [+ auth] + HTTP request/response. */
        const TickType_t t_round_start = xTaskGetTickCount();

        NetworkContext_t *nwk_ctx = app_corehttp_create_context(context->host, context->port, arm->tls_version,
                                                                arm->hybrid_kex, verbose);
        const TickType_t t_connected = xTaskGetTickCount();
        if (nwk_ctx == NULL)
        {
            PRINTF("[%3lu/%lu] %s | TLS connection failed\r\n", (unsigned long)round, (unsigned long)iterations,
                   arm->label);
            fail_rounds++;
            arm_fail[arm_idx]++;
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        if (verbose)
        {
            /* What the baseline client pays to check the server's RSA signature. */
            const mbedtls_x509_crt *crt = app_corehttp_peer_cert(nwk_ctx);
            if (crt != NULL)
            {
                app_hybrid_auth_bench_rsa_verify(&crt->pk, "live server cert key");
            }
        }

        /* --- Hybrid authentication: sign the session's exporter value --- */
        app_hybrid_auth_result_t auth = {0};
        int auth_hdr_len              = 0;
        uint32_t auth_round_ms        = 0;
        if (arm->hybrid_auth)
        {
            const TickType_t t_auth0 = xTaskGetTickCount();
            uint8_t exporter[32];
            int rc = auth_ready ? app_corehttp_export_keying_material(nwk_ctx, AUTH_EXPORTER_LABEL, exporter,
                                                                      sizeof(exporter))
                                : -1;
            if (rc == 0)
            {
                auth_hdr_len = app_hybrid_auth_sign_verify(exporter, sizeof(exporter), &auth, auth_hdr, 5120,
                                                           arm->hybrid_auth == 1);
            }
            auth_round_ms = (uint32_t)(xTaskGetTickCount() - t_auth0) * (uint32_t)portTICK_PERIOD_MS;
            if (rc != 0 || auth_hdr_len <= 0 || !auth.mldsa_ok || !auth.ecdsa_ok)
            {
                PRINTF("[%3lu/%lu] %s | hybrid auth FAILED (export %d, hdr %d, mldsa %d, ecdsa %d)\r\n",
                       (unsigned long)round, (unsigned long)iterations, arm->label, rc, auth_hdr_len, auth.mldsa_ok,
                       auth.ecdsa_ok);
                auth_fail[arm_idx]++;
            }
            if (verbose)
            {
                PRINTF("hybrid auth: ML-DSA sign %lu.%03lu ms, verify %lu.%03lu ms | ECDSA P-256 sign %lu.%03lu ms, "
                       "verify %lu.%03lu ms | header %d chars | self-verify %s\r\n",
                       (unsigned long)(auth.mldsa_sign_us / 1000), (unsigned long)(auth.mldsa_sign_us % 1000),
                       (unsigned long)(auth.mldsa_verify_us / 1000), (unsigned long)(auth.mldsa_verify_us % 1000),
                       (unsigned long)(auth.ecdsa_sign_us / 1000), (unsigned long)(auth.ecdsa_sign_us % 1000),
                       (unsigned long)(auth.ecdsa_verify_us / 1000), (unsigned long)(auth.ecdsa_verify_us % 1000),
                       auth_hdr_len, (auth.mldsa_ok && auth.ecdsa_ok) ? "OK" : "FAILED");
            }
        }

        HTTPRequestHeaders_t req_headers;
        HTTPRequestInfo_t req_info;
        HTTPResponse_t resp;
        HTTPStatus_t status;

        memset(&req_headers, 0x00, sizeof(req_headers));
        memset(&req_info, 0x00, sizeof(req_info));
        memset(&resp, 0x00, sizeof(resp));

        req_headers.pBuffer   = hdr_buf;
        req_headers.bufferLen = context->max_request_len;

        req_info.pMethod   = HTTP_METHOD_GET;
        req_info.methodLen = sizeof(HTTP_METHOD_GET) - 1;
        req_info.pPath     = context->path;
        req_info.pathLen   = strlen(context->path);
        req_info.pHost     = context->host;
        req_info.hostLen   = strlen(context->host);
        req_info.reqFlags  = HTTP_REQUEST_KEEP_ALIVE_FLAG;

        status = HTTPClient_InitializeRequestHeaders(&req_headers, &req_info);
        if (status == HTTPSuccess && arm->hybrid_auth && auth_hdr_len > 0)
        {
            status = HTTPClient_AddHeader(&req_headers, AUTH_HEADER_NAME, sizeof(AUTH_HEADER_NAME) - 1, auth_hdr,
                                          (size_t)auth_hdr_len);
        }
        if (status != HTTPSuccess)
        {
            PRINTF("[%3lu/%lu] Failed to build request headers (%d).\r\n", (unsigned long)round,
                   (unsigned long)iterations, status);
            app_corehttp_destroy_context(nwk_ctx);
            fail_rounds++;
            arm_fail[arm_idx]++;
            continue;
        }

        xport_interface.pNetworkContext = nwk_ctx;

        resp.pBuffer   = resp_buf;
        resp.bufferLen = context->max_response_len;

        const TickType_t t_http_start = xTaskGetTickCount();
        status                        = HTTPClient_Send(&xport_interface, &req_headers, NULL, 0, &resp, 0);
        const TickType_t t_round_end  = xTaskGetTickCount();

        const uint32_t http_round_ms = (uint32_t)(t_round_end - t_http_start) * (uint32_t)portTICK_PERIOD_MS;
        const uint32_t round_ms      = (uint32_t)(t_round_end - t_round_start) * (uint32_t)portTICK_PERIOD_MS;

        app_corehttp_stats_t stats;
        app_corehttp_get_stats(nwk_ctx, &stats);

        /* Everything in create_context that is neither TCP connect nor the handshake:
         * entropy/DRBG seeding, mbedtls_ssl_setup() buffer allocation, config. */
        const uint32_t connect_total_ms = (uint32_t)(t_connected - t_round_start) * (uint32_t)portTICK_PERIOD_MS;
        const uint32_t setup_ms = connect_total_ms - stats.tcp_connect_ms - stats.handshake_ms;

        if (status != HTTPSuccess)
        {
            app_corehttp_destroy_context(nwk_ctx);
            PRINTF("[%3lu/%lu] %s | HTTP request failed: %d\r\n", (unsigned long)round, (unsigned long)iterations,
                   arm->label, status);
            fail_rounds++;
            arm_fail[arm_idx]++;
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        if (verbose)
        {
            PRINTF("Response code: %d\r\nResponse body:\r\n", resp.statusCode);
            for (uint32_t i = 0; i < resp.bodyLen; i++)
            {
                if (resp.pBody[i] == '\n')
                {
                    PRINTF("\r");
                }
                PRINTF("%c", resp.pBody[i]);
            }
            PRINTF("\r\n\r\n");
        }

        app_corehttp_destroy_context(nwk_ctx);

        PRINTF("[%3lu/%lu] %s | setup %3lu | tcp %4lu | handshake %4lu (tx %4lu B, rx %5lu B) | auth %4lu | http %4lu | round %4lu ms | HTTP %d\r\n",
               (unsigned long)round, (unsigned long)iterations, arm->label, (unsigned long)setup_ms,
               (unsigned long)stats.tcp_connect_ms, (unsigned long)stats.handshake_ms,
               (unsigned long)stats.handshake_tx, (unsigned long)stats.handshake_rx, (unsigned long)auth_round_ms,
               (unsigned long)http_round_ms, (unsigned long)round_ms, resp.statusCode);

        setup_ms_s[ok_rounds] = setup_ms;
        tcp_ms[ok_rounds]     = stats.tcp_connect_ms;
        hs_ms[ok_rounds]      = stats.handshake_ms;
        auth_ms[ok_rounds]    = auth_round_ms;
        http_ms[ok_rounds]    = http_round_ms;
        tot_ms[ok_rounds]     = round_ms;
        arm_of[ok_rounds]     = (uint8_t)arm_idx;
        ok_rounds++;

        hs_tx_sum[arm_idx] += stats.handshake_tx;
        hs_rx_sum[arm_idx] += stats.handshake_rx;
        tx_sum[arm_idx] += stats.total_tx;
        rx_sum[arm_idx] += stats.total_rx;
        mldsa_sign_us[arm_idx] += auth.mldsa_sign_us;
        mldsa_verify_us[arm_idx] += auth.mldsa_verify_us;
        ecdsa_sign_us[arm_idx] += auth.ecdsa_sign_us;
        ecdsa_verify_us[arm_idx] += auth.ecdsa_verify_us;
        arm_ok[arm_idx]++;

        /* Give the server a moment to tear down the previous connection. */
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    PRINTF("\r\n=== Benchmark summary: %lu ok, %lu failed ===\r\n", (unsigned long)ok_rounds,
           (unsigned long)fail_rounds);
    for (uint32_t a = 0; a < n_arms; a++)
    {
        const uint32_t n = arm_ok[a];
        PRINTF("\r\n--- %s: %lu ok, %lu failed ---\r\n", arms[a].label, (unsigned long)n,
               (unsigned long)arm_fail[a]);
        if (n == 0U)
        {
            continue;
        }
        PRINTF("                  min   median   avg    max  (ms)\r\n");
        print_stat_line_for("TLS setup    ", setup_ms_s, arm_of, ok_rounds, (uint8_t)a, scratch);
        print_stat_line_for("TCP connect  ", tcp_ms, arm_of, ok_rounds, (uint8_t)a, scratch);
        print_stat_line_for("TLS handshake", hs_ms, arm_of, ok_rounds, (uint8_t)a, scratch);
        if (arms[a].hybrid_auth)
        {
            print_stat_line_for("Hybrid auth  ", auth_ms, arm_of, ok_rounds, (uint8_t)a, scratch);
        }
        print_stat_line_for("HTTP GET     ", http_ms, arm_of, ok_rounds, (uint8_t)a, scratch);
        print_stat_line_for("Full round   ", tot_ms, arm_of, ok_rounds, (uint8_t)a, scratch);
        PRINTF("Handshake I/O : avg tx %lu B, rx %lu B\r\n", (unsigned long)(hs_tx_sum[a] / n),
               (unsigned long)(hs_rx_sum[a] / n));
        PRINTF("Round I/O     : avg tx %lu B, rx %lu B\r\n", (unsigned long)(tx_sum[a] / n),
               (unsigned long)(rx_sum[a] / n));
        if (arms[a].hybrid_auth)
        {
            PRINTF("Auth (avg)    : ML-DSA sign %lu.%lu ms, verify %lu.%lu ms | ECDSA sign %lu.%lu ms, verify %lu.%lu ms | self-verify failures %lu\r\n",
                   (unsigned long)(mldsa_sign_us[a] / n / 1000), (unsigned long)(mldsa_sign_us[a] / n % 1000 / 100),
                   (unsigned long)(mldsa_verify_us[a] / n / 1000), (unsigned long)(mldsa_verify_us[a] / n % 1000 / 100),
                   (unsigned long)(ecdsa_sign_us[a] / n / 1000), (unsigned long)(ecdsa_sign_us[a] / n % 1000 / 100),
                   (unsigned long)(ecdsa_verify_us[a] / n / 1000), (unsigned long)(ecdsa_verify_us[a] / n % 1000 / 100),
                   (unsigned long)auth_fail[a]);
        }
    }
    if (ok_rounds > 0U)
    {
        PRINTF("\r\n(median is the number to compare: single network stalls distort min/avg/max;\r\n");
        PRINTF(" TCP connect is the network-quality control: it contains no crypto)\r\n");
    }
    PRINTF("=== Done ===\r\n");

free_exit:
    vPortFree(arm_of);
    vPortFree(scratch);
    vPortFree(tot_ms);
    vPortFree(http_ms);
    vPortFree(auth_ms);
    vPortFree(hs_ms);
    vPortFree(tcp_ms);
    vPortFree(setup_ms_s);
    vPortFree(auth_hdr);
    vPortFree(resp_buf);
    vPortFree(hdr_buf);
    vPortFree(context);
    vTaskDelete(NULL);
}

/* Insertion sort is plenty for a few hundred samples. */
static void sort_u32(uint32_t *v, uint32_t n)
{
    for (uint32_t i = 1; i < n; i++)
    {
        uint32_t key = v[i];
        uint32_t j   = i;
        while (j > 0 && v[j - 1] > key)
        {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = key;
    }
}

/* Copy the samples belonging to arm `want` into `scratch`, then print. */
static void print_stat_line_for(const char *label, const uint32_t *samples, const uint8_t *arm_of, uint32_t n,
                                uint8_t want, uint32_t *scratch)
{
    uint32_t m = 0;
    for (uint32_t i = 0; i < n; i++)
    {
        if (arm_of[i] == want)
        {
            scratch[m++] = samples[i];
        }
    }
    if (m > 0U)
    {
        print_stat_line(label, scratch, m);
    }
}

static void print_stat_line(const char *label, uint32_t *samples, uint32_t n)
{
    uint64_t sum = 0;
    for (uint32_t i = 0; i < n; i++)
    {
        sum += samples[i];
    }
    sort_u32(samples, n); /* sorts in place; samples are not needed afterwards */
    const uint32_t median = (n % 2U) ? samples[n / 2] : (samples[n / 2 - 1] + samples[n / 2]) / 2U;

    PRINTF("%s : %4lu   %4lu   %4lu   %4lu\r\n", label, (unsigned long)samples[0], (unsigned long)median,
           (unsigned long)(sum / n), (unsigned long)samples[n - 1]);
}
