/*
 * FOCAL hackathon - step 4: hybrid authentication (ML-DSA-65 + ECDSA P-256).
 * See app_hybrid_auth.h.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "fsl_debug_console.h"
#include "fsl_device_registers.h" /* DWT, SystemCoreClock */

#include "psa/crypto.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/psa_util.h"
#include "test/certs.h" /* mbedtls_test_srv_key_rsa_der: RSA-2048 reference key */

#include "mldsa_native.h"
#include "app_hybrid_auth.h"

/* ------------------------------------------------------------------------- */
/* Heap-backed aligned allocator for mldsa-native's large working buffers.   */
/* ------------------------------------------------------------------------- */
#define MLD_HEAP_ALIGN 64U

void *app_mld_aligned_alloc(size_t size)
{
    uint8_t *raw = pvPortMalloc(size + MLD_HEAP_ALIGN + sizeof(void *));
    if (raw == NULL)
    {
        return NULL;
    }
    uintptr_t aligned = ((uintptr_t)raw + sizeof(void *) + MLD_HEAP_ALIGN - 1U) & ~(uintptr_t)(MLD_HEAP_ALIGN - 1U);
    ((void **)aligned)[-1] = raw; /* stash the raw pointer just below the aligned block */
    return (void *)aligned;
}

void app_mld_aligned_free(void *p)
{
    if (p != NULL)
    {
        vPortFree(((void **)p)[-1]);
    }
}

/* ------------------------------------------------------------------------- */
/* DWT cycle counter                                                         */
/* ------------------------------------------------------------------------- */
static void dwt_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
static inline uint32_t dwt_now(void)
{
    return DWT->CYCCNT;
}
static inline uint32_t cyc_to_us(uint32_t cyc)
{
    return (uint32_t)(((uint64_t)cyc * 1000000ULL) / SystemCoreClock);
}
static void print_us(const char *label, uint32_t us, const char *note)
{
    PRINTF("  %-38s %5lu.%03lu ms  %s\r\n", label, (unsigned long)(us / 1000), (unsigned long)(us % 1000),
           note ? note : "");
}

/* ------------------------------------------------------------------------- */
/* Device keys                                                               */
/* ------------------------------------------------------------------------- */
static uint8_t *s_mldsa_pk; /* MLDSA65_PUBLICKEYBYTES = 1952 */
static uint8_t *s_mldsa_sk; /* MLDSA65_SECRETKEYBYTES = 4032 */
static uint8_t *s_mldsa_sig; /* MLDSA65_BYTES = 3309 */
static psa_key_id_t s_ecdsa_key = 0;
static int s_ready = 0;

/* Pure ML-DSA, empty context string: domain-separation prefix = 0x00 || 0x00. */
static uint8_t s_mld_prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES];
static size_t s_mld_prefix_len = 0;

int app_hybrid_auth_init(void)
{
    dwt_init();

    s_mldsa_pk  = pvPortMalloc(MLDSA65_PUBLICKEYBYTES);
    s_mldsa_sk  = pvPortMalloc(MLDSA65_SECRETKEYBYTES);
    s_mldsa_sig = pvPortMalloc(MLDSA65_BYTES);
    if (s_mldsa_pk == NULL || s_mldsa_sk == NULL || s_mldsa_sig == NULL)
    {
        PRINTF("hybrid_auth: allocation failed\r\n");
        return -1;
    }

    PRINTF("\r\n=== Hybrid authentication: generating device keys ===\r\n");

    /* ML-DSA-65 key pair from a 32-byte seed out of the PSA DRBG. */
    uint8_t seed[MLDSA_SEEDBYTES];
    psa_generate_random(seed, sizeof(seed));
    uint32_t t0 = dwt_now();
    int rc      = mldsa_keypair_internal(s_mldsa_pk, s_mldsa_sk, seed);
    uint32_t dt = dwt_now() - t0;
    memset(seed, 0, sizeof(seed));
    if (rc != 0)
    {
        PRINTF("hybrid_auth: ML-DSA-65 keypair failed (%d)\r\n", rc);
        return -2;
    }
    print_us("ML-DSA-65 keypair", cyc_to_us(dt), "pk 1952 B, sk 4032 B");

    s_mld_prefix_len = mldsa_prepare_domain_separation_prefix(s_mld_prefix, NULL, 0, NULL, 0, MLD_PREHASH_NONE);
    if (s_mld_prefix_len == 0)
    {
        PRINTF("hybrid_auth: domain separation prefix failed\r\n");
        return -3;
    }

    /* ECDSA P-256 key pair via PSA. */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    t0                  = dwt_now();
    psa_status_t status = psa_generate_key(&attr, &s_ecdsa_key);
    dt                  = dwt_now() - t0;
    if (status != PSA_SUCCESS)
    {
        PRINTF("hybrid_auth: ECDSA P-256 keygen failed (%ld)\r\n", (long)status);
        return -4;
    }
    print_us("ECDSA P-256 keypair", cyc_to_us(dt), "pk 64 B");

    s_ready = 1;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Sign + self-verify                                                        */
/* ------------------------------------------------------------------------- */
int app_hybrid_auth_sign_verify(const uint8_t *msg, size_t msg_len, app_hybrid_auth_result_t *res,
                                char *hdr, size_t hdr_cap)
{
    if (!s_ready)
    {
        return -1;
    }
    memset(res, 0, sizeof(*res));

    /* --- ML-DSA-65: hedged (randomised) signing, rnd from the PSA DRBG --- */
    uint8_t rnd[MLDSA_RNDBYTES];
    psa_generate_random(rnd, sizeof(rnd));
    uint32_t t0 = dwt_now();
    int rc = mldsa_signature_internal(s_mldsa_sig, msg, msg_len, s_mld_prefix, s_mld_prefix_len, rnd, s_mldsa_sk, 0);
    res->mldsa_sign_us = cyc_to_us(dwt_now() - t0);
    memset(rnd, 0, sizeof(rnd));
    if (rc != 0)
    {
        PRINTF("hybrid_auth: ML-DSA sign failed (%d)\r\n", rc);
        return -2;
    }
    res->mldsa_sig_len = MLDSA65_BYTES;

    t0                   = dwt_now();
    rc                   = mldsa_verify(s_mldsa_sig, msg, msg_len, NULL, 0, s_mldsa_pk);
    res->mldsa_verify_us = cyc_to_us(dwt_now() - t0);
    res->mldsa_ok        = (rc == 0);

    /* --- ECDSA P-256 over SHA-256(msg) --- */
    uint8_t h[32];
    size_t hlen = 0;
    psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, h, sizeof(h), &hlen);

    uint8_t ecdsa_sig[64];
    size_t slen         = 0;
    t0                  = dwt_now();
    psa_status_t status = psa_sign_hash(s_ecdsa_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), h, 32, ecdsa_sig,
                                        sizeof(ecdsa_sig), &slen);
    res->ecdsa_sign_us  = cyc_to_us(dwt_now() - t0);
    if (status != PSA_SUCCESS)
    {
        PRINTF("hybrid_auth: ECDSA sign failed (%ld)\r\n", (long)status);
        return -3;
    }
    res->ecdsa_sig_len = (uint32_t)slen;

    t0                   = dwt_now();
    status               = psa_verify_hash(s_ecdsa_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), h, 32, ecdsa_sig, slen);
    res->ecdsa_verify_us = cyc_to_us(dwt_now() - t0);
    res->ecdsa_ok        = (status == PSA_SUCCESS);

    /* --- Header value: mldsa65=<b64>;ecdsa-p256=<b64> --- */
    size_t pos = 0, olen = 0;
    const char *k1 = "mldsa65=";
    const char *k2 = ";ecdsa-p256=";
    if (hdr_cap < strlen(k1) + strlen(k2) + 8)
    {
        return -4;
    }
    memcpy(hdr + pos, k1, strlen(k1));
    pos += strlen(k1);
    if (mbedtls_base64_encode((unsigned char *)hdr + pos, hdr_cap - pos, &olen, s_mldsa_sig, MLDSA65_BYTES) != 0)
    {
        return -5;
    }
    pos += olen;
    if (hdr_cap - pos < strlen(k2) + 1)
    {
        return -6;
    }
    memcpy(hdr + pos, k2, strlen(k2));
    pos += strlen(k2);
    if (mbedtls_base64_encode((unsigned char *)hdr + pos, hdr_cap - pos, &olen, ecdsa_sig, slen) != 0)
    {
        return -7;
    }
    pos += olen;
    hdr[pos] = '\0';
    return (int)pos;
}

/* ------------------------------------------------------------------------- */
/* Micro-benchmarks                                                          */
/* ------------------------------------------------------------------------- */
static void sort_u32(uint32_t *v, int n)
{
    for (int i = 1; i < n; i++)
    {
        uint32_t key = v[i];
        int j        = i;
        while (j > 0 && v[j - 1] > key)
        {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = key;
    }
}

static void print_stats(const char *label, uint32_t *us, int n, const char *note)
{
    sort_u32(us, n);
    const uint32_t med = us[n / 2];
    PRINTF("  %-30s min %5lu.%03lu  med %5lu.%03lu  max %5lu.%03lu ms  %s\r\n", label,
           (unsigned long)(us[0] / 1000), (unsigned long)(us[0] % 1000), (unsigned long)(med / 1000),
           (unsigned long)(med % 1000), (unsigned long)(us[n - 1] / 1000), (unsigned long)(us[n - 1] % 1000),
           note ? note : "");
}

#define AUTH_BENCH_RUNS 10

void app_hybrid_auth_bench(void)
{
    if (!s_ready)
    {
        return;
    }
    uint32_t us[AUTH_BENCH_RUNS];
    uint8_t msg[32];
    uint8_t rnd[MLDSA_RNDBYTES];
    volatile int sink = 0; /* consumes warn_unused_result return values */
    psa_generate_random(msg, sizeof(msg));

    PRINTF("\r\n=== Authentication micro-benchmark (%d runs; ML-DSA signing is randomised) ===\r\n",
           AUTH_BENCH_RUNS);
    PRINTF("-- ML-DSA-65 (mldsa-native, portable C, REDUCE_RAM, heap buffers) --\r\n");

    uint8_t *pk = pvPortMalloc(MLDSA65_PUBLICKEYBYTES);
    uint8_t *sk = pvPortMalloc(MLDSA65_SECRETKEYBYTES);
    if (pk && sk)
    {
        uint8_t seed[MLDSA_SEEDBYTES];
        for (int i = 0; i < AUTH_BENCH_RUNS; i++)
        {
            psa_generate_random(seed, sizeof(seed));
            uint32_t t0 = dwt_now();
            sink |= mldsa_keypair_internal(pk, sk, seed);
            us[i] = cyc_to_us(dwt_now() - t0);
        }
        print_stats("ML-DSA-65 keypair", us, AUTH_BENCH_RUNS, "");
    }
    vPortFree(sk);
    vPortFree(pk);

    for (int i = 0; i < AUTH_BENCH_RUNS; i++)
    {
        psa_generate_random(rnd, sizeof(rnd));
        uint32_t t0 = dwt_now();
        sink |= mldsa_signature_internal(s_mldsa_sig, msg, sizeof(msg), s_mld_prefix, s_mld_prefix_len, rnd,
                                         s_mldsa_sk, 0);
        us[i] = cyc_to_us(dwt_now() - t0);
    }
    print_stats("ML-DSA-65 sign (32 B msg)", us, AUTH_BENCH_RUNS, "sig 3309 B");

    for (int i = 0; i < AUTH_BENCH_RUNS; i++)
    {
        uint32_t t0 = dwt_now();
        sink |= mldsa_verify(s_mldsa_sig, msg, sizeof(msg), NULL, 0, s_mldsa_pk);
        us[i] = cyc_to_us(dwt_now() - t0);
    }
    print_stats("ML-DSA-65 verify", us, AUTH_BENCH_RUNS, sink == 0 ? "all ok" : "ERRORS");

    /* --- RSA-2048 reference (mbedTLS test server key) — "today's" signature --- */
    PRINTF("-- RSA reference (mbedTLS test key, PKCS#1 v1.5, SHA-256) --\r\n");
    mbedtls_pk_context pk_rsa;
    mbedtls_pk_init(&pk_rsa);
    int rc = mbedtls_pk_parse_key(&pk_rsa, mbedtls_test_srv_key_rsa_der, mbedtls_test_srv_key_rsa_der_len, NULL, 0,
                                  mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
    if (rc == 0)
    {
        uint8_t h[32];
        size_t hlen = 0;
        psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), h, sizeof(h), &hlen);
        size_t bits   = mbedtls_pk_get_bitlen(&pk_rsa);
        uint8_t *sig  = pvPortMalloc(MBEDTLS_PK_SIGNATURE_MAX_SIZE);
        size_t siglen = 0;
        char note[32];
        snprintf(note, sizeof(note), "RSA-%lu", (unsigned long)bits);
        if (sig != NULL)
        {
            for (int i = 0; i < AUTH_BENCH_RUNS; i++)
            {
                uint32_t t0 = dwt_now();
                (void)mbedtls_pk_sign(&pk_rsa, MBEDTLS_MD_SHA256, h, 32, sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE, &siglen,
                                      mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
                us[i] = cyc_to_us(dwt_now() - t0);
            }
            print_stats("RSA sign", us, AUTH_BENCH_RUNS, note);
            for (int i = 0; i < AUTH_BENCH_RUNS; i++)
            {
                uint32_t t0 = dwt_now();
                (void)mbedtls_pk_verify(&pk_rsa, MBEDTLS_MD_SHA256, h, 32, sig, siglen);
                us[i] = cyc_to_us(dwt_now() - t0);
            }
            print_stats("RSA verify", us, AUTH_BENCH_RUNS, note);
            vPortFree(sig);
        }
    }
    else
    {
        PRINTF("  RSA test key parse failed: -0x%04x\r\n", (unsigned)-rc);
    }
    mbedtls_pk_free(&pk_rsa);
    PRINTF("=== authentication micro-benchmark done ===\r\n\r\n");
}

void app_hybrid_auth_bench_rsa_verify(const mbedtls_pk_context *pk, const char *label)
{
    /* RSA verify = one public-key exponentiation + compare; its cost does not
     * depend on the signature being valid, so a random signature of the right
     * length measures exactly what the baseline client pays per handshake. */
    if (pk == NULL || mbedtls_pk_get_type(pk) != MBEDTLS_PK_RSA)
    {
        return;
    }
    const size_t len = mbedtls_pk_get_len(pk);
    uint8_t *sig     = pvPortMalloc(len);
    uint8_t h[32];
    if (sig == NULL)
    {
        return;
    }
    psa_generate_random(h, sizeof(h));
    psa_generate_random(sig, len);
    sig[0] = 0; /* keep the integer below the modulus */
    uint32_t best = UINT32_MAX;
    for (int i = 0; i < 5; i++)
    {
        uint32_t t0 = dwt_now();
        (void)mbedtls_pk_verify((mbedtls_pk_context *)pk, MBEDTLS_MD_SHA256, h, 32, sig, len);
        uint32_t dt = dwt_now() - t0;
        if (dt < best)
        {
            best = dt;
        }
    }
    char lbl[48];
    snprintf(lbl, sizeof(lbl), "RSA-%lu verify (%s)", (unsigned long)mbedtls_pk_get_bitlen(pk), label);
    print_us(lbl, cyc_to_us(best), "baseline client cost per handshake");
    vPortFree(sig);
}
