/*
 * FOCAL hackathon - on-board micro-benchmark of the cryptographic primitives
 * involved in the hybrid handshake, measured with the Cortex-M33 DWT cycle
 * counter (cycle-exact, independent of the 1 ms RTOS tick).
 *
 * Purpose: break the ~40 ms that X25519MLKEM768 adds to the TLS 1.3 handshake
 * into its parts (Keccak/SHAKE hashing, NTT, sampling, network), so that the
 * acceleration study (PowerQuad / NPU / ELS) targets the right thing.
 *
 * Every number is the MINIMUM over N runs: interrupts (RTOS tick, Ethernet)
 * can only add cycles, so the minimum is the clean cost of the operation.
 */

#include <stdint.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "fsl_debug_console.h"
#include "fsl_device_registers.h" /* DWT, CoreDebug, SystemCoreClock */

#include "psa/crypto.h"
#include "mlkem_native.h"

#include "app_pqc_bench.h"

/* --- mlkem-native internals (exported from the single-compilation-unit build) --- */
/* ML-KEM-768: K = 3 polynomials of 256 int16 coefficients. */
#define MLK_K 3
#define MLK_N 256
typedef struct { int16_t coeffs[MLK_N]; } bench_poly;
typedef struct { bench_poly vec[MLK_K]; } bench_polyvec;
typedef struct { int16_t coeffs[MLK_N / 2]; } bench_poly_mulcache;
typedef struct { bench_poly_mulcache vec[MLK_K]; } bench_polyvec_mulcache;

extern void mlkem_polyvec_ntt(bench_polyvec *r);
extern void mlkem_polyvec_invntt_tomont(bench_polyvec *r);
extern void mlkem_polyvec_mulcache_compute(bench_polyvec_mulcache *x, const bench_polyvec *a);
extern void mlkem_gen_matrix(bench_polyvec *a, const uint8_t seed[32], int transposed);
extern void mlkem_keccakf1600x4_permute(uint64_t *state); /* 4 lanes = 4 permutations in C */
extern void mlkem_sha3_512(uint8_t *out, const uint8_t *in, size_t inlen);
extern void mlkem_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* --- DWT cycle counter ---------------------------------------------------- */
static void dwt_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    DWT->CYCCNT = 0;
}
static inline uint32_t dwt_now(void)
{
    return DWT->CYCCNT;
}

/* Print "label : cycles  x.xxx ms" for the minimum over runs. */
static void report(const char *label, uint32_t min_cycles, const char *note)
{
    /* integer ms with 3 decimals (= µs), avoiding float printf */
    const uint32_t us = (uint32_t)(((uint64_t)min_cycles * 1000000ULL) / SystemCoreClock);
    PRINTF("  %-38s %9lu cyc  %5lu.%03lu ms  %s\r\n", label, (unsigned long)min_cycles,
           (unsigned long)(us / 1000), (unsigned long)(us % 1000), note ? note : "");
}

#define BENCH_RUNS 10

/* Time `stmt` BENCH_RUNS times and keep the minimum cycle count. */
#define BENCH(label, note, stmt)                                 \
    do                                                           \
    {                                                            \
        uint32_t best = UINT32_MAX;                              \
        for (int _r = 0; _r < BENCH_RUNS; _r++)                  \
        {                                                        \
            uint32_t t0 = dwt_now();                             \
            stmt;                                                \
            uint32_t dt = dwt_now() - t0;                        \
            if (dt < best) best = dt;                            \
        }                                                        \
        report(label, best, note);                               \
    } while (0)

void app_pqc_bench_run(void)
{
    dwt_init();

    PRINTF("\r\n=== On-board crypto micro-benchmark (DWT cycles @ %lu MHz, min of %d runs) ===\r\n",
           (unsigned long)(SystemCoreClock / 1000000UL), BENCH_RUNS);

    /* Heap buffers: keep the task stack free for the real handshake later. */
    uint8_t *pk    = pvPortMalloc(MLKEM768_PUBLICKEYBYTES);
    uint8_t *sk    = pvPortMalloc(MLKEM768_SECRETKEYBYTES);
    uint8_t *ct    = pvPortMalloc(MLKEM768_CIPHERTEXTBYTES);
    uint8_t *ss1   = pvPortMalloc(MLKEM_BYTES);
    uint8_t *ss2   = pvPortMalloc(MLKEM_BYTES);
    uint8_t *coins = pvPortMalloc(2 * MLKEM_SYMBYTES);
    bench_polyvec *mat          = pvPortMalloc(sizeof(bench_polyvec) * MLK_K);
    bench_polyvec *pv           = pvPortMalloc(sizeof(bench_polyvec));
    bench_polyvec_mulcache *mc  = pvPortMalloc(sizeof(bench_polyvec_mulcache));
    uint64_t *kstate            = pvPortMalloc(4 * 25 * sizeof(uint64_t));
    uint8_t *buf1k              = pvPortMalloc(1024);
    uint8_t *hash               = pvPortMalloc(64);

    if (!pk || !sk || !ct || !ss1 || !ss2 || !coins || !mat || !pv || !mc || !kstate || !buf1k || !hash)
    {
        PRINTF("pqc_bench: allocation failed, skipping\r\n");
        goto out;
    }

    psa_generate_random(coins, 2 * MLKEM_SYMBYTES);
    psa_generate_random(buf1k, 1024);
    memset(kstate, 0, 4 * 25 * sizeof(uint64_t));
    memset(pv, 0, sizeof(*pv));

    /* ---- 1. ML-KEM-768 top-level operations (what the TLS client runs) ---- */
    PRINTF("-- ML-KEM-768 (mlkem-native, portable C) --\r\n");
    volatile int rc = 0; /* sink for warn_unused_result */
    BENCH("mlkem768 keypair (client, ClientHello)", "", rc |= mlkem_keypair_derand(pk, sk, coins));
    BENCH("mlkem768 encaps (server side, ref)", "", rc |= mlkem_enc_derand(ct, ss1, pk, coins));
    BENCH("mlkem768 decaps (client, key schedule)", "", rc |= mlkem_dec(ss2, ct, sk));
    if (rc != 0)
    {
        PRINTF("  (an ML-KEM call returned an error: %d)\r\n", rc);
    }
    PRINTF("  (encaps/decaps shared secret %s)\r\n", memcmp(ss1, ss2, MLKEM_BYTES) == 0 ? "MATCH" : "MISMATCH!");

    /* ---- 2. building blocks ---- */
    PRINTF("-- building blocks --\r\n");
    BENCH("keccak-f1600 x4 (4 permutations)", "SHAKE/SHA3 core", mlkem_keccakf1600x4_permute(kstate));
    BENCH("sha3-512 (64 B in) = G", "", mlkem_sha3_512(hash, coins, 64));
    BENCH("shake256 33 B -> 128 B = PRF", "", mlkem_shake256(buf1k, 128, coins, 33));
    BENCH("gen_matrix A (9 polys, SHAKE128)", "rej. sampling", mlkem_gen_matrix(mat, coins, 0));
    BENCH("polyvec NTT (3 polys)", "", mlkem_polyvec_ntt(pv));
    BENCH("polyvec invNTT+tomont (3 polys)", "", mlkem_polyvec_invntt_tomont(pv));
    BENCH("polyvec mulcache (3 polys)", "", mlkem_polyvec_mulcache_compute(mc, pv));

    /* ---- 3. classical counterparts via PSA (ELS/PKC hardware where the port supports it) ---- */
    PRINTF("-- classical (PSA / NXP ELS-PKC port) --\r\n");
    {
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_id_t x_key = 0, x_key2 = 0;
        uint8_t x_pub[32], x_pub2[32], x_ss[32];
        size_t olen = 0;

        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
        psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
        psa_set_key_bits(&attr, 255);

        /* peer key, generated once */
        if (psa_generate_key(&attr, &x_key2) == PSA_SUCCESS &&
            psa_export_public_key(x_key2, x_pub2, sizeof(x_pub2), &olen) == PSA_SUCCESS)
        {
            BENCH("x25519 keygen + export pub", "", {
                psa_generate_key(&attr, &x_key);
                psa_export_public_key(x_key, x_pub, sizeof(x_pub), &olen);
                psa_destroy_key(x_key);
            });
            psa_generate_key(&attr, &x_key);
            BENCH("x25519 shared secret", "", psa_raw_key_agreement(PSA_ALG_ECDH, x_key, x_pub2, 32, x_ss, 32, &olen));
            psa_destroy_key(x_key);
            psa_destroy_key(x_key2);
        }
        else
        {
            PRINTF("  x25519: PSA key generation not available in this port\r\n");
        }
    }
    {
        /* ECDSA P-256 verify: the classical half of the future hybrid authentication. */
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_id_t key = 0;
        uint8_t sig[64], h[32];
        size_t slen = 0;

        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attr, 256);
        memcpy(h, coins, 32);
        if (psa_generate_key(&attr, &key) == PSA_SUCCESS &&
            psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), h, 32, sig, sizeof(sig), &slen) == PSA_SUCCESS)
        {
            BENCH("ecdsa p256 sign", "", psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), h, 32, sig, sizeof(sig), &slen));
            BENCH("ecdsa p256 verify", "auth, client side", psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), h, 32, sig, slen));
            psa_destroy_key(key);
        }
        else
        {
            PRINTF("  ecdsa p256: PSA key generation / sign not available in this port\r\n");
        }
    }
    {
        size_t hlen = 0;
        BENCH("sha-256 (1 KB) via PSA", "", psa_hash_compute(PSA_ALG_SHA_256, buf1k, 1024, hash, 32, &hlen));
        BENCH("sha3-256 (1 KB) via mlkem shake256", "software", mlkem_shake256(hash, 32, buf1k, 1024));
    }

    PRINTF("=== micro-benchmark done ===\r\n\r\n");

out:
    vPortFree(hash);
    vPortFree(buf1k);
    vPortFree(kstate);
    vPortFree(mc);
    vPortFree(pv);
    vPortFree(mat);
    vPortFree(coins);
    vPortFree(ss2);
    vPortFree(ss1);
    vPortFree(ct);
    vPortFree(sk);
    vPortFree(pk);
}
