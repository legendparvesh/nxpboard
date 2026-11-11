/*
 * Copyright 2023-2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>

/* LwIP */
#include "ethernetif.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/netdb.h"
#include "lwip/netifapi.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

#include "FreeRTOS.h"
#include "task.h"

/* App */
#include "app_ca_bundle.h"
#include "app_mbedtls_socket.h"

#ifndef MBEDTLS_DEBUG_THRESHOLD
#define MBEDTLS_DEBUG_THRESHOLD 0
#endif /* MBEDTLS_DEBUG_THRESHOLD */

#ifndef APP_DRBG_SEED_ONCE
/* 0 = seed a fresh CTR-DRBG per connection (baseline behaviour, ~74 ms each),
 * 1 = seed once at first use and reuse it (migration optimisation). */
#define APP_DRBG_SEED_ONCE 0
#endif /* APP_DRBG_SEED_ONCE */

static int app_mbedtls_socket_tcp_send(void *fd, unsigned char const *buf, size_t len);
static int app_mbedtls_socket_tcp_recv(void *fd, unsigned char const *buf, size_t len);
static const char *app_mbedtls_socket_strerr(int code);

#if defined(MBEDTLS_DEBUG_C) && (MBEDTLS_DEBUG_THRESHOLD > 0)
static void app_mbedtls_socket_debug(void *ctx, int level, const char *file, int line, const char *str);
#endif /* defined(MBEDTLS_DEBUG_C) && (MBEDTLS_DEBUG_THRESHOLD > 0) */

int app_mbedtls_socket_connect(void *param, char *host, uint16_t port)
{
    int ret;

    app_mbedtls_socket_t *sock = param;

    mbedtls_ssl_init(&sock->ctx_ssl);
    mbedtls_ssl_config_init(&sock->ssl_config);
    mbedtls_ctr_drbg_init(&sock->ctx_ctr_drbg);
    mbedtls_x509_crt_init(&sock->ca_cert);

    mbedtls_entropy_init(&sock->ctx_entropy);

    /* Entropy + CTR-DRBG seeding costs a fixed ~74 ms on this board (TRNG
     * gathering). The baseline does it on every connection. */
    mbedtls_ctr_drbg_context *rng;
    const TickType_t t_seed0 = xTaskGetTickCount();
#if APP_DRBG_SEED_ONCE
    /* Seed one DRBG on first use and share it across connections. The client
     * task is the only user, so no locking is needed here; a multi-task
     * application would wrap this in a mutex. */
    static mbedtls_entropy_context s_entropy;
    static mbedtls_ctr_drbg_context s_ctr_drbg;
    static bool s_seeded = false;
    if (!s_seeded)
    {
        mbedtls_entropy_init(&s_entropy);
        mbedtls_ctr_drbg_init(&s_ctr_drbg);
        ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, mbedtls_entropy_func, &s_entropy, NULL, 0);
        if (ret != 0)
        {
            PRINTF("CTR DRBG seed failed with error: %s\r\n", app_mbedtls_socket_strerr(ret));
            return ret;
        }
        s_seeded = true;
    }
    rng = &s_ctr_drbg;
#else
    ret = mbedtls_ctr_drbg_seed(&sock->ctx_ctr_drbg, mbedtls_entropy_func, &sock->ctx_entropy, NULL, 0);
    if (ret != 0)
    {
        PRINTF("CTR DRBG seed failed with error: %s\r\n", app_mbedtls_socket_strerr(ret));

        return ret;
    }
    rng = &sock->ctx_ctr_drbg;
#endif
    const TickType_t t_seed1 = xTaskGetTickCount();
    if (sock->verbose)
    {
        PRINTF("setup: entropy + CTR-DRBG seed took %lu ms (APP_DRBG_SEED_ONCE=%d)\r\n",
               (unsigned long)((t_seed1 - t_seed0) * portTICK_PERIOD_MS), (int)APP_DRBG_SEED_ONCE);
    }

    /* Accept either an IPv4 or an IPv6 literal. */
    struct sockaddr_storage sa;
    socklen_t sa_len;
    int af;
    memset(&sa, 0, sizeof(sa));

    struct sockaddr_in *sa4  = (struct sockaddr_in *)&sa;
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sa;
    if (inet_pton(AF_INET, host, &sa4->sin_addr) == 1)
    {
        af               = AF_INET;
        sa4->sin_family  = AF_INET;
        sa4->sin_port    = PP_HTONS(port);
        sa_len           = sizeof(*sa4);
    }
    else if (inet_pton(AF_INET6, host, &sa6->sin6_addr) == 1)
    {
        af               = AF_INET6;
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port   = PP_HTONS(port);
        sa_len           = sizeof(*sa6);
    }
    else
    {
        PRINTF("Failed to parse IP literal '%s'\r\n", host);
        return -1;
    }

    sock->lwip_fd = socket(af, SOCK_STREAM, 0);
    if (sock->lwip_fd < 0)
    {
        return -2;
    }

    if (sock->verbose)
    {
        PRINTF("Connecting to [%s]:%u...\r\n", host, (unsigned)port);
    }
    const TickType_t t_tcp_start = xTaskGetTickCount();
    ret = connect(sock->lwip_fd, (struct sockaddr *)&sa, sa_len);
    if (ret != 0)
    {
        PRINTF("Unable to connect() to [%s]:%u\r\n", host, (unsigned)port);
        goto close_exit;
    }
    sock->tcp_connect_ms = (uint32_t)(xTaskGetTickCount() - t_tcp_start) * (uint32_t)portTICK_PERIOD_MS;

    ret = mbedtls_ssl_config_defaults(&sock->ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        PRINTF("Failed to preset SSL config with error: %s\r\n", app_mbedtls_socket_strerr(ret));

        goto close_exit;
    }

#if defined(MBEDTLS_DEBUG_C) && (MBEDTLS_DEBUG_THRESHOLD > 0)
    mbedtls_ssl_conf_dbg(&sock->ssl_config, app_mbedtls_socket_debug, NULL);
    mbedtls_debug_set_threshold(MBEDTLS_DEBUG_THRESHOLD);
#endif /* defined(MBEDTLS_DEBUG_C) && (MBEDTLS_DEBUG_THRESHOLD > 0) */

    mbedtls_ssl_conf_authmode(&sock->ssl_config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&sock->ssl_config, mbedtls_ctr_drbg_random, rng);

    /* Key-exchange groups, in order of preference. The hybrid group is only
     * meaningful for TLS 1.3; the TLS 1.2 code path ignores it. */
    static const uint16_t groups_hybrid[] = {
#if defined(MBEDTLS_SSL_TLS1_3_HYBRID_MLKEM)
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519_MLKEM768,
#endif
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
        0,
    };
    static const uint16_t groups_classic[] = {
        MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
        MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
        0,
    };
    mbedtls_ssl_conf_groups(&sock->ssl_config, sock->hybrid_kex ? groups_hybrid : groups_classic);

    /* Pin the protocol version per connection so the A/B benchmark can
     * alternate TLS 1.2 and TLS 1.3 under identical network conditions. */
    if (sock->tls_version == 2)
    {
        mbedtls_ssl_conf_min_tls_version(&sock->ssl_config, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&sock->ssl_config, MBEDTLS_SSL_VERSION_TLS1_2);
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    else if (sock->tls_version == 3)
    {
        mbedtls_ssl_conf_min_tls_version(&sock->ssl_config, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_max_tls_version(&sock->ssl_config, MBEDTLS_SSL_VERSION_TLS1_3);
    }
#endif
    /* else: leave the mbedTLS default (negotiate the highest both support) */

    const TickType_t t_setup0 = xTaskGetTickCount();
    ret = mbedtls_ssl_setup(&sock->ctx_ssl, &sock->ssl_config);
    const TickType_t t_setup1 = xTaskGetTickCount();
    if (ret != 0)
    {
        PRINTF("Failed to setup SSL context with error: %s\r\n", app_mbedtls_socket_strerr(ret));

        goto close_exit;
    }
    if (sock->verbose)
    {
        PRINTF("setup: mbedtls_ssl_setup took %lu ms\r\n",
               (unsigned long)((t_setup1 - t_setup0) * portTICK_PERIOD_MS));
    }

    ret = mbedtls_ssl_set_hostname(&sock->ctx_ssl, host);
    if (ret != 0)
    {
        PRINTF("Failed to set SSL hostname with error: %s\r\n", app_mbedtls_socket_strerr(ret));

        goto close_exit;
    }

    /* Pass the whole socket struct so the BIO callbacks can count bytes. */
    mbedtls_ssl_set_bio(&sock->ctx_ssl, sock, app_mbedtls_socket_tcp_send,
                        (mbedtls_ssl_recv_t *)app_mbedtls_socket_tcp_recv, NULL);

    if (sock->verbose)
    {
        PRINTF("Performing SSL/TLS handshake...\r\n");
    }

    sock->total_tx = 0;
    sock->total_rx = 0;

    const TickType_t t_start = xTaskGetTickCount();
    do
    {
        ret = mbedtls_ssl_handshake(&sock->ctx_ssl);

        if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            PRINTF("SSL handshake error: %s\r\n", app_mbedtls_socket_strerr(ret));
            goto close_exit;
        }
    } while (ret != 0);
    const TickType_t t_end = xTaskGetTickCount();

    const uint32_t handshake_ticks = (uint32_t)(t_end - t_start);

    sock->handshake_ms = handshake_ticks * (uint32_t)portTICK_PERIOD_MS;
    sock->handshake_tx = sock->total_tx;
    sock->handshake_rx = sock->total_rx;

    if (!sock->verbose)
    {
        return 0;
    }

    PRINTF("SSL: Protocol: %s, cipher suite: %s\r\n", mbedtls_ssl_get_version(&sock->ctx_ssl),
           mbedtls_ssl_get_ciphersuite(&sock->ctx_ssl));
    PRINTF("=== TLS handshake took %lu ms (%lu RTOS ticks), %lu B sent, %lu B received ===\r\n",
           (unsigned long)sock->handshake_ms, (unsigned long)handshake_ticks,
           (unsigned long)sock->handshake_tx, (unsigned long)sock->handshake_rx);

    ret = mbedtls_ssl_get_record_expansion(&sock->ctx_ssl);
    if (ret == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE)
    {
        PRINTF("SSL: Compression is used, record expansion is unavailable.\r\n");
    }
    else if (ret >= 0)
    {
        PRINTF("SSL: Record expansion: %d\r\n", ret);
    }

    if (mbedtls_ssl_get_peer_cert(&sock->ctx_ssl) != NULL)
    {
        char *buf = pvPortMalloc(MBEDTLS_SSL_IN_CONTENT_LEN + 1);
        if (buf == NULL)
        {
            PRINTF("SSL: Failed to allocate certificate info buffer.\r\n");

            goto close_exit;
        }

        PRINTF("SSL: Peer certificate information:\n");
        mbedtls_x509_crt_info((char *)buf, MBEDTLS_SSL_IN_CONTENT_LEN, "\r>>> ",
                              mbedtls_ssl_get_peer_cert(&sock->ctx_ssl));
        PRINTF("%s\r\n", buf);

        vPortFree(buf);
    }

    return 0;

close_exit:
    close(sock->lwip_fd);

    return ret;
}

void app_mbedtls_socket_close(void *param)
{
    app_mbedtls_socket_t *sock = param;

    close(sock->lwip_fd);

    mbedtls_x509_crt_free(&sock->ca_cert);
    mbedtls_ssl_free(&sock->ctx_ssl);
    mbedtls_ssl_config_free(&sock->ssl_config);
    mbedtls_ctr_drbg_free(&sock->ctx_ctr_drbg);
    mbedtls_entropy_free(&sock->ctx_entropy);
}

int app_mbedtls_socket_send(void *param, uint8_t *buf, int size)
{
    int ret;

    app_mbedtls_socket_t *sock = param;

    ret = mbedtls_ssl_write(&sock->ctx_ssl, buf, size);
    if (ret < 0)
    {
        PRINTF("SSL: send() failed with error: %s\r\n", app_mbedtls_socket_strerr(ret));
    }

    return ret;
}

int app_mbedtls_socket_recv(void *param, uint8_t *buf, int size)
{
    int ret;

    app_mbedtls_socket_t *sock = param;

    ret = mbedtls_ssl_read(&sock->ctx_ssl, buf, size);
    if (ret < 0)
    {
        PRINTF("SSL: recv() failed with error: %s\r\n", app_mbedtls_socket_strerr(ret));
    }

    return ret;
}

static int app_mbedtls_socket_tcp_send(void *ctx, unsigned char const *buf, size_t len)
{
    app_mbedtls_socket_t *sock = ctx;

    int ret = lwip_send(sock->lwip_fd, buf, len, 0);
    if (ret > 0)
    {
        sock->total_tx += (uint32_t)ret;
    }
    return ret;
}

static int app_mbedtls_socket_tcp_recv(void *ctx, unsigned char const *buf, size_t len)
{
    app_mbedtls_socket_t *sock = ctx;

    int ret = lwip_recv(sock->lwip_fd, (void *)buf, len, 0);
    if (ret > 0)
    {
        sock->total_rx += (uint32_t)ret;
    }
    return ret;
}

static const char *app_mbedtls_socket_strerr(int code)
{
    static char buffer[8];
    const char *msg;

    msg = mbedtls_high_level_strerr(code);
    if (msg != NULL)
    {
        return msg;
    }

    msg = mbedtls_low_level_strerr(code);
    if (msg != NULL)
    {
        return msg;
    }
    else if (code < 0)
    {
        snprintf(buffer, sizeof(buffer), "-0x%04x", -code);
        return buffer;
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "0x%04x", code);
        return buffer;
    }
}

#if defined(MBEDTLS_DEBUG_C) && (MBEDTLS_DEBUG_THRESHOLD > 0)
static void app_mbedtls_socket_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    const char *file_name = file;

    (void)ctx;
    (void)level;

    for (; *file != '\0'; file++)
    {
        if (*file == '/' || *file == '\\')
        {
            file_name = file + 1;
        }
    }

    mbedtls_printf("%s:%04d: %s", file_name, line, str);
}
#endif /* defined(MBEDTLS_DEBUG_C) && (MBEDTLS_DEBUG_THRESHOLD > 0) */
