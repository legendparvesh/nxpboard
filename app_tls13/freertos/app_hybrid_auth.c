/*
 * FOCAL hackathon - step 4: hybrid authentication (ML-DSA + ECDSA P-256).
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

#include <setjmp.h>
#include "task.h"
#include "app_dualcore.h"
#include "app_mld_arena.h"

/* Sizes and names follow the parameter set chosen in app_mldsa_config.h. */
#define MLD_STR_(x) #x
#define MLD_STR(x) MLD_STR_(x)
#define MLD_LEVEL_STR MLD_STR(MLD_CONFIG_PARAMETER_SET)
#define MLD_NAME "ML-DSA-" MLD_LEVEL_STR
#define MLD_PK_BYTES MLDSA_PUBLICKEYBYTES(MLD_CONFIG_PARAMETER_SET)
#define MLD_SK_BYTES MLDSA_SECRETKEYBYTES(MLD_CONFIG_PARAMETER_SET)
#define MLD_SIG_BYTES MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET)

/* ------------------------------------------------------------------------- */
/* Heap-backed aligned allocator for mldsa-native's large working buffers.   */
/* ------------------------------------------------------------------------- */
/* mldsa-native's working buffers come from a bump arena (app_mld_arena.c:
 * provides app_mld_aligned_alloc/free), carved from the FreeRTOS heap once.
 * A bump arena is what lets the dual-core race abandon an attempt safely. */
static int arena_init(void)
{
    void *buf = pvPortMalloc(APP_MLD_ARENA_BYTES + 64);
    if (buf == NULL)
    {
        return -1;
    }
    app_mld_arena_init(buf, APP_MLD_ARENA_BYTES + 64);
    return 0;
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
static uint8_t *s_mldsa_pk; /* MLD_PK_BYTES = 1952 */
static uint8_t *s_mldsa_sk; /* MLD_SK_BYTES = 4032 */
static uint8_t *s_mldsa_sig; /* MLD_SIG_BYTES = 3309 */
static psa_key_id_t s_ecdsa_key = 0;
static int s_ready = 0;

/* Pure ML-DSA, empty context string: domain-separation prefix = 0x00 || 0x00. */
static uint8_t s_mld_prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES];
static size_t s_mld_prefix_len = 0;

int app_hybrid_auth_init(void)
{
    dwt_init();

    s_mldsa_pk  = pvPortMalloc(MLD_PK_BYTES);
    s_mldsa_sk  = pvPortMalloc(MLD_SK_BYTES);
    s_mldsa_sig = pvPortMalloc(MLD_SIG_BYTES);
    if (s_mldsa_pk == NULL || s_mldsa_sk == NULL || s_mldsa_sig == NULL)
    {
        PRINTF("hybrid_auth: allocation failed\r\n");
        return -1;
    }

    PRINTF("\r\n=== Hybrid authentication: generating device keys ===\r\n");

    /* ML-DSA key pair from a 32-byte seed out of the PSA DRBG. */
    uint8_t seed[MLDSA_SEEDBYTES];
    psa_generate_random(seed, sizeof(seed));
    uint32_t t0 = dwt_now();
    if (arena_init() != 0)
    {
        PRINTF("hybrid_auth: no memory for the ML-DSA arena\r\n");
        return -1;
    }
    int rc      = mldsa_keypair_internal(s_mldsa_pk, s_mldsa_sk, seed);
    uint32_t dt = dwt_now() - t0;
    memset(seed, 0, sizeof(seed));
    if (rc != 0)
    {
        PRINTF("hybrid_auth: ML-DSA keypair failed (%d)\r\n", rc);
        return -2;
    }
    print_us(MLD_NAME " keypair", cyc_to_us(dt), "pk/sk sized per level");

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
/* --- Step 6: dual-core signing race ---------------------------------------
 * Core 1 signs the same message with its own randomness while core 0 signs
 * here. Whoever finishes first wins; the other attempt is abandoned: core 1 by
 * an abort event, core 0 by longjmp out of the library from the Keccak hook
 * (app_mldsa_fips202_backend.h) that fires when core 1 reports done. */
static jmp_buf s_race_jmp;
static volatile int s_race_armed;

int app_mld_abort_poll(void)
{
    /* Abandon core 0's attempt only for a usable result from core 1; if core 1
     * reports an error or an abort, core 0 simply keeps signing. */
    return s_race_armed && app_dualcore_done() && app_dualcore_shm()->status == APP_DC_DONE;
}

void app_mld_abort_jump(void)
{
    longjmp(s_race_jmp, 1);
}

#if APP_DUALCORE
static int sign_race(const uint8_t *msg, size_t msg_len, const uint8_t *rnd0, int *winner)
{
    volatile app_dualcore_shm_t *shm = app_dualcore_shm();
    uint8_t rnd1[MLDSA_RNDBYTES];
    volatile int rc = -1;

    psa_generate_random(rnd1, sizeof(rnd1));
    shm->msg     = msg;
    shm->msg_len = (uint32_t)msg_len;
    shm->pre     = s_mld_prefix;
    shm->pre_len = (uint32_t)s_mld_prefix_len;
    shm->sk      = s_mldsa_sk;
    shm->sig_len = 0;
    memcpy((void *)shm->rnd, rnd1, sizeof(rnd1));
    memset(rnd1, 0, sizeof(rnd1));

    *winner = 0;
    app_mld_arena_reset(0);
    if (app_dualcore_cmd(APP_DC_CMD_SIGN) != 0)
    {
        /* core 1 busy or gone: sign alone */
        app_dualcore_stats.sign_core1_err++;
        return mldsa_signature_internal(s_mldsa_sig, msg, msg_len, s_mld_prefix, s_mld_prefix_len, rnd0, s_mldsa_sk, 0);
    }

    s_race_armed = 1;
    if (setjmp(s_race_jmp) == 0)
    {
        rc = mldsa_signature_internal(s_mldsa_sig, msg, msg_len, s_mld_prefix, s_mld_prefix_len, rnd0, s_mldsa_sk, 0);
        s_race_armed = 0;
        /* core 0 finished first (or both did): stop core 1 and let it park */
        app_dualcore_abort();
        int st = app_dualcore_wait(300);
        if (st == APP_DC_DONE) app_dualcore_stats.sign_both_done++;
        else if (st == APP_DC_ABORTED) app_dualcore_stats.sign_aborted++;
        else app_dualcore_stats.sign_core1_err++;
        app_dualcore_stats.sign_core0_wins++;
    }
    else
    {
        /* core 1 reported first: core 0's attempt was abandoned inside the library */
        s_race_armed = 0;
        app_mld_arena_reset(1);
        int st = app_dualcore_wait(10);
        if (st == APP_DC_DONE && shm->sig_len == MLD_SIG_BYTES)
        {
            memcpy(s_mldsa_sig, (const void *)shm->sig, MLD_SIG_BYTES);
            rc      = 0;
            *winner = 1;
            app_dualcore_stats.sign_core1_wins++;
            app_dualcore_stats.core1_sign_cycles_last = shm->cycles;
        }
        else
        {
            app_dualcore_stats.sign_core1_err++;
            app_mld_arena_reset(0);
            rc = mldsa_signature_internal(s_mldsa_sig, msg, msg_len, s_mld_prefix, s_mld_prefix_len, rnd0, s_mldsa_sk, 0);
        }
    }
    app_dualcore_stats.core1_arena_peak = shm->arena_peak;
    memset((void *)shm->rnd, 0, sizeof(shm->rnd));
    memset((void *)shm->sig, 0, sizeof(shm->sig));
    shm->sig_len = 0;
    return rc;
}
#endif /* APP_DUALCORE */

int app_hybrid_auth_sign_verify(const uint8_t *msg, size_t msg_len, app_hybrid_auth_result_t *res,
                                char *hdr, size_t hdr_cap, int self_verify)
{
    if (!s_ready)
    {
        return -1;
    }
    memset(res, 0, sizeof(*res));

    /* --- ML-DSA: hedged (randomised) signing, rnd from the PSA DRBG --- */
    uint8_t rnd[MLDSA_RNDBYTES];
    psa_generate_random(rnd, sizeof(rnd));
    uint32_t t0 = dwt_now();
    int rc;
    res->mldsa_core = 0;
#if APP_DUALCORE
    if (app_dualcore_enabled && app_dualcore_ready())
    {
        rc = sign_race(msg, msg_len, rnd, &res->mldsa_core);
    }
    else
#endif
    {
        app_mld_arena_reset(0);
        rc = mldsa_signature_internal(s_mldsa_sig, msg, msg_len, s_mld_prefix, s_mld_prefix_len, rnd, s_mldsa_sk, 0);
    }
    res->mldsa_sign_us = cyc_to_us(dwt_now() - t0);
    memset(rnd, 0, sizeof(rnd));
    if (rc != 0)
    {
        PRINTF("hybrid_auth: ML-DSA sign failed (%d)\r\n", rc);
        return -2;
    }
    res->mldsa_sig_len = MLD_SIG_BYTES;

    if (self_verify)
    {
        t0                   = dwt_now();
        rc                   = mldsa_verify(s_mldsa_sig, msg, msg_len, NULL, 0, s_mldsa_pk);
        res->mldsa_verify_us = cyc_to_us(dwt_now() - t0);
        res->mldsa_ok        = (rc == 0);
    }
    else
    {
        res->mldsa_ok = 1; /* deployment mode: the peer verifies */
    }

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

    if (self_verify)
    {
        t0                   = dwt_now();
        status               = psa_verify_hash(s_ecdsa_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), h, 32, ecdsa_sig, slen);
        res->ecdsa_verify_us = cyc_to_us(dwt_now() - t0);
        res->ecdsa_ok        = (status == PSA_SUCCESS);
    }
    else
    {
        res->ecdsa_ok = 1;
    }

    /* --- Header value: mldsa65=<b64>;ecdsa-p256=<b64> --- */
    size_t pos = 0, olen = 0;
    const char *k1 = "mldsa" MLD_LEVEL_STR "=";
    const char *k2 = ";ecdsa-p256=";
    if (hdr_cap < strlen(k1) + strlen(k2) + 8)
    {
        return -4;
    }
    memcpy(hdr + pos, k1, strlen(k1));
    pos += strlen(k1);
    if (mbedtls_base64_encode((unsigned char *)hdr + pos, hdr_cap - pos, &olen, s_mldsa_sig, MLD_SIG_BYTES) != 0)
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

/* ------------------------------------------------------------------------- */
/* Step 6: dual-core self-test                                               */
/* ------------------------------------------------------------------------- */
int app_hybrid_auth_dualcore_selftest(void)
{
#if APP_DUALCORE
    extern int mlkem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
    extern int mlkem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
    extern int mbedtls_ssl_tls13_hybrid_mlkem_dec_begin(const unsigned char *ct, const unsigned char *sk);
    extern int mbedtls_ssl_tls13_hybrid_mlkem_dec_end(unsigned char *ss);

    if (!s_ready || !app_dualcore_ready())
    {
        return -1;
    }
    volatile app_dualcore_shm_t *shm = app_dualcore_shm();
    uint8_t msg[32], rnd[MLDSA_RNDBYTES];
    int fails = 0, ok, st;
    TickType_t t0;
    uint32_t ms;

    psa_generate_random(msg, sizeof(msg));
    PRINTF("\r\n=== Dual-core self-test ===\r\n");

    /* 1. core 1 signs alone, core 0 verifies */
    psa_generate_random(rnd, sizeof(rnd));
    shm->msg     = msg;
    shm->msg_len = sizeof(msg);
    shm->pre     = s_mld_prefix;
    shm->pre_len = (uint32_t)s_mld_prefix_len;
    shm->sk      = s_mldsa_sk;
    memcpy((void *)shm->rnd, rnd, sizeof(rnd));
    t0 = xTaskGetTickCount();
    st = (app_dualcore_cmd(APP_DC_CMD_SIGN) == 0) ? app_dualcore_wait(3000) : -1;
    ms = (uint32_t)(xTaskGetTickCount() - t0) * portTICK_PERIOD_MS;
    ok = (st == APP_DC_DONE) && shm->sig_len == MLD_SIG_BYTES &&
         mldsa_verify((const uint8_t *)shm->sig, msg, sizeof(msg), NULL, 0, s_mldsa_pk) == 0;
    PRINTF("  core 1 signs, core 0 verifies     : %s  (%lu ms wall, %lu cycles on core 1, arena peak %lu B)\r\n",
           ok ? "PASS" : "FAIL", (unsigned long)ms, (unsigned long)shm->cycles, (unsigned long)shm->arena_peak);
    fails += !ok;

    /* 2. abort: start a signature on core 1, abandon it after 5 ms */
    psa_generate_random(rnd, sizeof(rnd));
    memcpy((void *)shm->rnd, rnd, sizeof(rnd));
    if (app_dualcore_cmd(APP_DC_CMD_SIGN) == 0)
    {
        vTaskDelay(pdMS_TO_TICKS(5));
        t0 = xTaskGetTickCount();
        app_dualcore_abort();
        st = app_dualcore_wait(500);
        ms = (uint32_t)(xTaskGetTickCount() - t0) * portTICK_PERIOD_MS;
    }
    else
    {
        st = -1;
        ms = 0;
    }
    ok = (st == APP_DC_ABORTED);
    PRINTF("  abort while core 1 is signing     : %s  (parked %lu ms after the request, status %d)\r\n",
           ok ? "PASS" : "FAIL", (unsigned long)ms, st);
    fails += !ok;

    /* 3. the race, three times, each result verified */
    {
        int wins[2] = {0, 0}, race_ok = 1;
        for (int i = 0; i < 3; i++)
        {
            int core = 0;
            psa_generate_random(rnd, sizeof(rnd));
            int rc = sign_race(msg, sizeof(msg), rnd, &core);
            ok     = (rc == 0) && mldsa_verify(s_mldsa_sig, msg, sizeof(msg), NULL, 0, s_mldsa_pk) == 0;
            if (ok) wins[core]++;
            race_ok &= ok;
        }
        PRINTF("  signing race x3, verified         : %s  (won by core 0: %d, core 1: %d)\r\n",
               race_ok ? "PASS" : "FAIL", wins[0], wins[1]);
        fails += !race_ok;
    }

    /* 4. ML-KEM-768 decapsulation on core 1 */
    {
        uint8_t *pk = pvPortMalloc(1184), *sk = pvPortMalloc(2400), *ct = pvPortMalloc(1088);
        uint8_t ss0[32], ss1[32], coins[64];
        ok = 0;
        if (pk && sk && ct)
        {
            volatile int sink = 0;
            psa_generate_random(coins, sizeof(coins));
            sink |= mlkem_keypair_derand(pk, sk, coins);
            psa_generate_random(coins, 32);
            sink |= mlkem_enc_derand(ct, ss0, pk, coins);
            int prev             = app_dualcore_enabled;
            app_dualcore_enabled = 1;
            ok = (sink == 0) && mbedtls_ssl_tls13_hybrid_mlkem_dec_begin(ct, sk) == 0 &&
                 mbedtls_ssl_tls13_hybrid_mlkem_dec_end(ss1) == 0 && memcmp(ss0, ss1, 32) == 0;
            app_dualcore_enabled = prev;
        }
        PRINTF("  ML-KEM-768 decaps on core 1       : %s  (%lu cycles on core 1)\r\n", ok ? "PASS" : "FAIL",
               (unsigned long)shm->cycles);
        fails += !ok;

        /* 5. what the handshake gains: hybrid shared secret, sequential on core 0
         *    (decaps then X25519) vs decaps on core 1 while core 0 does X25519. */
        if (ok)
        {
            extern int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
            psa_key_attributes_t attr = psa_key_attributes_init();
            psa_key_id_t k1 = 0, k2 = 0;
            uint8_t pub2[32], x[32];
            size_t len = 0;
            psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
            psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
            psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
            psa_set_key_bits(&attr, 255);
            if (psa_generate_key(&attr, &k1) == PSA_SUCCESS && psa_generate_key(&attr, &k2) == PSA_SUCCESS &&
                psa_export_public_key(k2, pub2, sizeof(pub2), &len) == PSA_SUCCESS)
            {
                uint32_t best_seq = UINT32_MAX, best_par = UINT32_MAX;
                int prev             = app_dualcore_enabled;
                app_dualcore_enabled = 1;
                for (int i = 0; i < 5; i++)
                {
                    uint32_t t0 = dwt_now();
                    (void)mlkem_dec(ss1, ct, sk);
                    (void)psa_raw_key_agreement(PSA_ALG_ECDH, k1, pub2, 32, x, sizeof(x), &len);
                    uint32_t dt = dwt_now() - t0;
                    if (dt < best_seq) best_seq = dt;

                    t0 = dwt_now();
                    (void)mbedtls_ssl_tls13_hybrid_mlkem_dec_begin(ct, sk);
                    (void)psa_raw_key_agreement(PSA_ALG_ECDH, k1, pub2, 32, x, sizeof(x), &len);
                    (void)mbedtls_ssl_tls13_hybrid_mlkem_dec_end(ss1);
                    dt = dwt_now() - t0;
                    if (dt < best_par) best_par = dt;
                }
                app_dualcore_enabled = prev;
                PRINTF("  hybrid shared secret, core 0 only : %lu.%03lu ms (ML-KEM decaps then X25519)\r\n",
                       (unsigned long)(best_seq / 150000), (unsigned long)((best_seq / 150) % 1000));
                PRINTF("  hybrid shared secret, two cores   : %lu.%03lu ms (decaps on core 1 || X25519 on core 0)\r\n",
                       (unsigned long)(best_par / 150000), (unsigned long)((best_par / 150) % 1000));
            }
            psa_destroy_key(k1);
            psa_destroy_key(k2);
        }
        vPortFree(ct);
        vPortFree(sk);
        vPortFree(pk);
    }

    memset(&app_dualcore_stats, 0, sizeof(app_dualcore_stats)); /* the benchmark starts from zero */
    PRINTF("=== dual-core self-test %s ===\r\n", fails ? "FAILED" : "passed");
    return fails ? -1 : 0;
#else
    return -1;
#endif
}

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
    PRINTF("-- ML-DSA (mldsa-native, portable C, REDUCE_RAM, heap buffers) --\r\n");

    uint8_t *pk = pvPortMalloc(MLD_PK_BYTES);
    uint8_t *sk = pvPortMalloc(MLD_SK_BYTES);
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
        print_stats(MLD_NAME " keypair", us, AUTH_BENCH_RUNS, "");
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
    print_stats(MLD_NAME " sign (32 B msg)", us, AUTH_BENCH_RUNS, "sig sized per level");

    for (int i = 0; i < AUTH_BENCH_RUNS; i++)
    {
        uint32_t t0 = dwt_now();
        sink |= mldsa_verify(s_mldsa_sig, msg, sizeof(msg), NULL, 0, s_mldsa_pk);
        us[i] = cyc_to_us(dwt_now() - t0);
    }
    print_stats(MLD_NAME " verify", us, AUTH_BENCH_RUNS, sink == 0 ? "all ok" : "ERRORS");

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
