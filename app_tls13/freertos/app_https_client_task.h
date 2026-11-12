/*
 * Copyright 2023-2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __APP_HTTPS_CLIENT_TASK_H__
#define __APP_HTTPS_CLIENT_TASK_H__

#include "FreeRTOS.h"
#include <stddef.h>

typedef struct https_client_task_context
{
    char *host;
    uint16_t port;
    char *path;
    size_t max_request_len;
    size_t max_response_len;
    uint32_t iterations; /* number of connect+GET rounds to benchmark */
    /* Which configurations to benchmark; multi-arm modes interleave the arms round by round
     * so every arm sees the same network conditions:
     *   0 = TLS 1.3 classic vs TLS 1.2            (2 arms)
     *   2 = TLS 1.2 only
     *   3 = TLS 1.3 classic only
     *   4 = TLS 1.3 hybrid vs TLS 1.3 classic     (2 arms)
     *   5 = TLS 1.3 hybrid (X25519MLKEM768) only
     *   6 = TLS 1.3 hybrid vs TLS 1.3 classic vs TLS 1.2  (3 arms)
     *   7 = hybrid KEX + hybrid AUTH (ML-DSA-65 + ECDSA) vs hybrid KEX vs TLS 1.3 vs TLS 1.2 (4 arms)
     *   8 = hybrid KEX + hybrid AUTH only
     *   9 = hybrid AUTH sign-only (deployment) vs hybrid AUTH with self-verify vs hybrid KEX
     *       vs TLS 1.3 vs TLS 1.2 (5 arms)
     *  10 = hybrid KEX with NTTs on the PowerQuad vs hybrid KEX (CPU NTT) vs TLS 1.3 vs TLS 1.2
     *  11 = hybrid KEX + hybrid AUTH sign-only (ML-DSA-44 + ECDSA), ML-KEM NTT on CPU vs on the
     *       PowerQuad (2 arms, the deployment configuration and its accelerated variant)
     *  12 = deployment configuration with the hybrid key share precomputed during the TCP
     *       connect vs generated inline (2 arms)
     *  13 = deployment configuration + precompute, with core 1 (ML-DSA signing race, ML-KEM
     *       decapsulation on core 1) vs single core (2 arms); needs the dual-core build */
    uint32_t tls_mode;
} https_client_task_context_t;

void app_https_client_task_init(https_client_task_context_t *context,
                                const configSTACK_DEPTH_TYPE stack_depth,
                                UBaseType_t priority);

#endif /* __APP_HTTPS_CLIENT_TASK_H__ */
