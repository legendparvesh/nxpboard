/*
 * FOCAL hackathon - step 4: hybrid authentication (ML-DSA-65 + ECDSA P-256),
 * device side. The board holds one key pair of each kind, signs the TLS 1.3
 * exporter value of the live connection with both, verifies both itself
 * (self-verify), and ships the signatures to the server in a request header.
 */
#ifndef APP_HYBRID_AUTH_H
#define APP_HYBRID_AUTH_H

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/pk.h"

/* Timings (DWT cycles converted to µs) and sizes of one sign + self-verify. */
typedef struct
{
    uint32_t mldsa_sign_us;
    uint32_t mldsa_verify_us;
    uint32_t ecdsa_sign_us;
    uint32_t ecdsa_verify_us;
    uint32_t mldsa_sig_len; /* 3309 for ML-DSA-65 */
    uint32_t ecdsa_sig_len; /* 64 for P-256 (r||s) */
    int mldsa_ok;           /* 1 = self-verify passed */
    int ecdsa_ok;
} app_hybrid_auth_result_t;

/* Generate the device key pairs (once). Prints key-generation times. 0 on success. */
int app_hybrid_auth_init(void);

/* Sign `msg` with ML-DSA and ECDSA P-256; if self_verify != 0 also verify both
 * (demo mode: no external verifier). Writes the header value
 * "mldsa<level>=<base64>;ecdsa-p256=<base64>" into hdr (NUL-terminated).
 * Returns the header value length, or a negative error. */
int app_hybrid_auth_sign_verify(const uint8_t *msg, size_t msg_len, app_hybrid_auth_result_t *res,
                                char *hdr, size_t hdr_cap, int self_verify);

/* Micro-benchmark: ML-DSA-65 keypair/sign/verify (min/median/max) and the
 * RSA-2048 "today" reference (mbedTLS test key). */
void app_hybrid_auth_bench(void);

/* Time an RSA verify with the given public key (e.g. the live server's RSA-3072
 * certificate key): the operation the baseline client performs per handshake. */
void app_hybrid_auth_bench_rsa_verify(const mbedtls_pk_context *pk, const char *label);

#endif /* APP_HYBRID_AUTH_H */
