/*
 * FOCAL hackathon - precomputed hybrid key share.
 *
 * The client task is idle for ~20 ms while the TCP connect is in flight. A
 * low-priority helper task uses that window to generate the next ML-KEM-768
 * keypair and X25519 key, and the patched mbedTLS (ssl_tls13_client.c,
 * MBEDTLS_SSL_TLS1_3_HYBRID_MLKEM_PRECOMPUTED) takes them when it writes the
 * ClientHello instead of generating them on the critical path.
 *
 * Every key share is used for exactly one connection. The helper only runs
 * while the client task is blocked (lower priority, and the client waits for it
 * right after connect() returns), so two tasks never use PSA crypto at the same
 * time - this mbedTLS build has no threading support.
 */
#ifndef APP_KEYSHARE_H
#define APP_KEYSHARE_H

#include <stdint.h>

/* Runtime switch, set per benchmark arm: 0 = generate inline (as before), 1 = precompute. */
extern volatile int app_keyshare_enabled;

/* Create the helper task. Returns 0 on success. */
int app_keyshare_init(void);

/* Ask the helper to prepare one hybrid key share (no-op if one is ready or in progress). */
void app_keyshare_request(void);

/* Block until the helper is idle again (returns at once if nothing was requested). */
void app_keyshare_wait(void);

/* Counters for the benchmark summary. */
void app_keyshare_stats(uint32_t *generated, uint32_t *taken, uint32_t *fallbacks, uint32_t *stack_used_bytes);

#endif /* APP_KEYSHARE_H */
