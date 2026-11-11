/*
 * Copyright 2023-2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __APP_MBEDTLS_SOCKET_H__
#define __APP_MBEDTLS_SOCKET_H__

#include <stdbool.h>
#include <stdint.h>

/* MbedTLS */
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/x509.h"
#include "test/certs.h"

typedef struct
{
    mbedtls_entropy_context ctx_entropy;
    mbedtls_ctr_drbg_context ctx_ctr_drbg;
    mbedtls_ssl_context ctx_ssl;
    mbedtls_ssl_config ssl_config;
    mbedtls_x509_crt ca_cert;
    int lwip_fd;

    /* Set by the caller before connect(): print protocol/cipher/certificate details. */
    bool verbose;
    /* Set by the caller before connect(): 2 = force TLS 1.2, 3 = force TLS 1.3, 0 = negotiate. */
    int tls_version;
    /* Set by the caller before connect(): 1 = offer X25519MLKEM768 first (hybrid PQ key
     * exchange, TLS 1.3 only), 0 = classical X25519 / P-256 only. */
    int hybrid_kex;

    /* Filled in by connect(): benchmark data for this connection. */
    uint32_t tcp_connect_ms; /* wall-clock time of the TCP connect() */
    uint32_t handshake_ms;   /* wall-clock time of mbedtls_ssl_handshake() */
    uint32_t handshake_tx;   /* TCP bytes sent during the handshake */
    uint32_t handshake_rx;   /* TCP bytes received during the handshake */
    uint32_t total_tx;       /* TCP bytes sent over the whole connection */
    uint32_t total_rx;       /* TCP bytes received over the whole connection */
} app_mbedtls_socket_t;

int app_mbedtls_socket_connect(void *param, char *host, uint16_t port);
void app_mbedtls_socket_close(void *param);
int app_mbedtls_socket_send(void *param, uint8_t *buf, int size);
int app_mbedtls_socket_recv(void *param, uint8_t *buf, int size);

#endif /* __APP_MBEDTLS_SOCKET_H__ */
