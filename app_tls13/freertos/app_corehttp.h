/*
 * Copyright 2023-2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __APP_COREHTTP_H__
#define __APP_COREHTTP_H__

#include <stdint.h>

/* coreHTTP */
#include "core_http_client.h"

#include <stdbool.h>

/*! Benchmark data for one connection, see app_corehttp_get_stats(). */
typedef struct
{
    uint32_t tcp_connect_ms;
    uint32_t handshake_ms;
    uint32_t handshake_tx;
    uint32_t handshake_rx;
    uint32_t total_tx;
    uint32_t total_rx;
} app_corehttp_stats_t;

/* tls_version: 2 = force TLS 1.2, 3 = force TLS 1.3, 0 = negotiate.
 * hybrid_kex:  1 = offer X25519MLKEM768 first, 0 = classical groups only. */
NetworkContext_t *app_corehttp_create_context(char *host, uint16_t port, int tls_version, int hybrid_kex,
                                              bool verbose);
void app_corehttp_destroy_context(NetworkContext_t *ctx);
void app_corehttp_get_stats(NetworkContext_t *ctx, app_corehttp_stats_t *stats);

/* TLS exporter (RFC 8446 §7.5): `len` bytes bound to this session, labelled `label`. 0 on success. */
int app_corehttp_export_keying_material(NetworkContext_t *ctx, const char *label, uint8_t *out, size_t len);

/* Peer certificate (NULL if none). */
const mbedtls_x509_crt *app_corehttp_peer_cert(NetworkContext_t *ctx);
int32_t app_corehttp_send(NetworkContext_t *ctx, const void *buf, size_t size);
int32_t app_corehttp_recv(NetworkContext_t *ctx, void *buf, size_t size);

#endif /* __APP_COREHTTP_H__ */
