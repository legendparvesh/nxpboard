/*
 * FOCAL hackathon - ML-KEM NTT on the PowerQuad matrix engine. See app_pq_ntt.h.
 */

#include <stdint.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "fsl_debug_console.h"
#include "fsl_device_registers.h"
#include "fsl_powerquad.h"

#include "psa/crypto.h"
#include "app_pq_ntt.h"

#define Q 3329
#define TILE 16
#define NT 8 /* 128 / 16 tiles per dimension */

/* Limb split. The twiddles W are 6-bit limbs (W = 64*hi + lo, hi <= 52), the
 * coefficients x are 5-bit limbs (x = 1024*x2 + 32*x1 + x0, x2 <= 3).
 *
 * Why 5-bit and not 6-bit for x: the matrix engine clamps every output at
 * +32767 even with the output format set to 32-bit (run 16 caught it:
 * "engine 32767 vs cpu 34870"). A block output is a 16-term sum of limb
 * products, so the limbs must satisfy 16 * max(W limb) * max(x limb) < 32768:
 * 16 * 63 * 31 = 31248 fits, 16 * 63 * 63 = 63504 does not. With 6-bit x limbs
 * ~1 in 10 000 coefficients came out wrong (runs 14/15). */
#define BCOLS 6 /* even x0,x1,x2 | odd x0,x1,x2 */

extern const int16_t app_pq_w_lo[NT * NT * TILE * TILE];
extern const int16_t app_pq_w_hi[NT * NT * TILE * TILE];

volatile int app_pq_ntt_enabled = 0;

/* Operands must be in RAM and word-aligned for the engine. */
static int16_t s_b[128][BCOLS] __attribute__((aligned(4)));      /* coefficient limbs, see BCOLS */
static int32_t s_tmp[TILE][BCOLS] __attribute__((aligned(4)));   /* one block product */
static int32_t s_acc_lo[128][BCOLS] __attribute__((aligned(4))); /* W_lo * B */
static int32_t s_acc_hi[128][BCOLS] __attribute__((aligned(4))); /* W_hi * B */

void app_pq_ntt_init(void)
{
    pq_config_t cfg;

    PQ_Init(POWERQUAD); /* enables the clock and resets the block */
    PQ_GetDefaultConfig(&cfg);
    cfg.inputAFormat = kPQ_16Bit;
    cfg.inputBFormat = kPQ_16Bit;
    cfg.outputFormat = kPQ_32Bit;
    cfg.tmpFormat    = kPQ_32Bit;
    cfg.machineFormat = kPQ_Float;
    cfg.inputAPrescale = cfg.inputBPrescale = cfg.outputPrescale = cfg.tmpPrescale = 0;
    PQ_SetConfig(POWERQUAD, &cfg);
}

/* One 16x16 (tile of W) times 16x6 (block of B) product, result into s_tmp. */
static inline void pq_block(const int16_t *w_tile, const int16_t *b_block)
{
    PQ_MatrixMultiplication(POWERQUAD, POWERQUAD_MAKE_MATRIX_LEN(TILE, TILE, BCOLS), (void *)w_tile, (void *)b_block,
                            s_tmp);
    PQ_WaitDone(POWERQUAD);
    /* The engine's last result write may still be in the bus write buffer when
     * BUSY clears; make sure it has landed before the CPU reads s_tmp. */
    __DSB();
    __ISB();
}

/* CPU reference of one block product, for diagnosing mismatches. */
static void cpu_block(const int16_t *w_tile, const int16_t *b_block, int32_t out[TILE][BCOLS])
{
    for (int i = 0; i < TILE; i++)
        for (int c = 0; c < BCOLS; c++)
        {
            int32_t s = 0;
            for (int k = 0; k < TILE; k++) s += (int32_t)w_tile[i * TILE + k] * b_block[k * BCOLS + c];
            out[i][c] = s;
        }
}

void app_pq_ntt(int16_t p[256])
{
    /* 1. Split input into [0,q) and 5-bit limbs, even/odd interleaved -> B (128x6). */
    for (int j = 0; j < 128; j++)
    {
        int16_t e = p[2 * j], o = p[2 * j + 1];
        if (e < 0) e += Q;
        if (o < 0) o += Q;
        s_b[j][0] = (int16_t)(e & 31);
        s_b[j][1] = (int16_t)((e >> 5) & 31);
        s_b[j][2] = (int16_t)(e >> 10);
        s_b[j][3] = (int16_t)(o & 31);
        s_b[j][4] = (int16_t)((o >> 5) & 31);
        s_b[j][5] = (int16_t)(o >> 10);
    }

    /* 2. Tiled products: for each row tile, accumulate the 8 column tiles. */
    for (int tr = 0; tr < NT; tr++)
    {
        int32_t *acc_lo = &s_acc_lo[tr * TILE][0];
        int32_t *acc_hi = &s_acc_hi[tr * TILE][0];
        memset(acc_lo, 0, TILE * BCOLS * sizeof(int32_t));
        memset(acc_hi, 0, TILE * BCOLS * sizeof(int32_t));
        for (int tc = 0; tc < NT; tc++)
        {
            const int16_t *b_block = &s_b[tc * TILE][0];
            const int tile_idx     = (tr * NT + tc) * TILE * TILE;

            pq_block(&app_pq_w_lo[tile_idx], b_block);
            for (int k = 0; k < TILE * BCOLS; k++) acc_lo[k] += ((int32_t *)s_tmp)[k];

            pq_block(&app_pq_w_hi[tile_idx], b_block);
            for (int k = 0; k < TILE * BCOLS; k++) acc_hi[k] += ((int32_t *)s_tmp)[k];
        }
    }

    /* 3. Recombine limbs: W*x = (64*Whi + Wlo) * (x0 + 32*x1 + 1024*x2), then mod q.
     * Each accumulator column is a sum over 128 terms < 128 * 3329^2 < 2^31. */
    for (int i = 0; i < 128; i++)
    {
        int32_t even = (s_acc_lo[i][0] + 32 * s_acc_lo[i][1] + 1024 * s_acc_lo[i][2]) +
                       64 * (s_acc_hi[i][0] + 32 * s_acc_hi[i][1] + 1024 * s_acc_hi[i][2]);
        int32_t odd  = (s_acc_lo[i][3] + 32 * s_acc_lo[i][4] + 1024 * s_acc_lo[i][5]) +
                       64 * (s_acc_hi[i][3] + 32 * s_acc_hi[i][4] + 1024 * s_acc_hi[i][5]);
        p[2 * i]     = (int16_t)(even % Q);
        p[2 * i + 1] = (int16_t)(odd % Q);
    }
}

/* ------------------------------------------------------------------------- */
/* Self-test and benchmark                                                   */
/* ------------------------------------------------------------------------- */
typedef struct { int16_t coeffs[256]; } bench_poly;
typedef struct { bench_poly vec[3]; } bench_polyvec;
extern void mlkem_polyvec_ntt(bench_polyvec *r); /* goes through the backend hook */

static inline uint32_t dwt_now(void) { return DWT->CYCCNT; }

static void fill_random_poly(int16_t p[256])
{
    uint16_t raw[256];
    psa_generate_random((uint8_t *)raw, sizeof(raw));
    for (int i = 0; i < 256; i++) p[i] = (int16_t)(raw[i] % Q) - (int16_t)(Q / 2); /* centred, |p| < q */
}

void app_pq_ntt_bench(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    bench_polyvec *sw = pvPortMalloc(sizeof(bench_polyvec));
    bench_polyvec *hw = pvPortMalloc(sizeof(bench_polyvec));
    if (sw == NULL || hw == NULL)
    {
        PRINTF("pq_ntt: allocation failed\r\n");
        vPortFree(sw); vPortFree(hw);
        return;
    }

    PRINTF("-- ML-KEM NTT on the PowerQuad matrix engine --\r\n");

    /* Engine arithmetic check: random block products (5-bit x limbs, lo and hi
     * W tiles) vs CPU. The clamp fault of runs 14/15 hit ~1 in 10 000 blocks,
     * so the sample has to be tens of thousands of blocks to be meaningful. */
    {
        int32_t ref[TILE][BCOLS];
        int bad_blocks = 0, bad_outputs = 0;
        const int blocks = 40000;
        for (int t = 0; t < blocks; t++)
        {
            uint8_t rnd[128 * BCOLS];
            psa_generate_random(rnd, sizeof(rnd));
            for (int k = 0; k < 128 * BCOLS; k++) ((int16_t *)s_b)[k] = (int16_t)(rnd[k] & 31);
            const int tile          = (rnd[0] % (NT * NT)) * TILE * TILE;
            const int16_t *w_tile   = (rnd[2] & 1) ? &app_pq_w_hi[tile] : &app_pq_w_lo[tile];
            const int16_t *b_block  = &s_b[(rnd[1] % NT) * TILE][0];
            pq_block(w_tile, b_block);
            cpu_block(w_tile, b_block, ref);
            if (memcmp(ref, s_tmp, sizeof(ref)) != 0)
            {
                for (int i = 0; i < TILE; i++)
                    for (int c = 0; c < BCOLS; c++)
                        if (ref[i][c] != s_tmp[i][c])
                        {
                            if (bad_outputs < 4)
                                PRINTF("    block mismatch: tile %d W_%s out[%d][%d] engine %ld vs cpu %ld\r\n",
                                       tile / (TILE * TILE), (rnd[2] & 1) ? "hi" : "lo", i, c, (long)s_tmp[i][c],
                                       (long)ref[i][c]);
                            bad_outputs++;
                        }
                bad_blocks++;
            }
        }
        PRINTF("  engine check: %d random 16x16x%d block products vs CPU, %d blocks / %d outputs wrong -> %s\r\n",
               blocks, BCOLS, bad_blocks, bad_outputs, bad_blocks == 0 ? "PASS" : "FAIL");
    }

    /* Correctness: PowerQuad NTT == software NTT (mod q) on random polynomials. */
    int bad = 0;
    const int trials = 200;
    for (int t = 0; t < trials; t++)
    {
        for (int v = 0; v < 3; v++) fill_random_poly(sw->vec[v].coeffs);
        memcpy(hw, sw, sizeof(*sw));
        app_pq_ntt_enabled = 0;
        mlkem_polyvec_ntt(sw);
        app_pq_ntt_enabled = 1;
        mlkem_polyvec_ntt(hw);
        for (int v = 0; v < 3; v++)
            for (int i = 0; i < 256; i++)
            {
                int32_t a = ((sw->vec[v].coeffs[i] % Q) + Q) % Q;
                int32_t b = ((hw->vec[v].coeffs[i] % Q) + Q) % Q;
                if (a != b)
                {
                    if (bad < 5)
                        PRINTF("    NTT mismatch: trial %d poly %d coeff %d: engine %ld vs cpu %ld\r\n", t, v, i, (long)b,
                               (long)a);
                    bad++;
                }
            }
    }
    app_pq_ntt_enabled = 0;
    PRINTF("  correctness: %d random polyvecs (%d NTTs, %d coefficients), %d mismatches -> %s\r\n", trials, trials * 3,
           trials * 3 * 256, bad, bad == 0 ? "PASS" : "FAIL");

    /* Raw engine cost: one 16x16 * 16x6 block product incl. wait. */
    {
        uint32_t best = UINT32_MAX;
        for (int r = 0; r < 20; r++)
        {
            uint32_t t0 = dwt_now();
            pq_block(app_pq_w_lo, &s_b[0][0]);
            uint32_t dt = dwt_now() - t0;
            if (dt < best) best = dt;
        }
        const unsigned long macs = TILE * TILE * BCOLS;
        PRINTF("  one 16x16 x 16x%d block product (%lu MAC)  : %6lu cycles  (%lu.%02lu cycles/MAC)\r\n", BCOLS, macs,
               (unsigned long)best, (unsigned long)(best / macs), (unsigned long)((best * 100 / macs) % 100));
    }

    /* NTT of one polynomial: software vs PowerQuad (min of 20). */
    uint32_t best_sw = UINT32_MAX, best_hw = UINT32_MAX;
    for (int r = 0; r < 20; r++)
    {
        fill_random_poly(sw->vec[0].coeffs);
        memcpy(hw->vec[0].coeffs, sw->vec[0].coeffs, sizeof(sw->vec[0].coeffs));

        app_pq_ntt_enabled = 0;
        uint32_t t0 = dwt_now();
        mlkem_polyvec_ntt(sw); /* 3 NTTs */
        uint32_t dt = (dwt_now() - t0) / 3;
        if (dt < best_sw) best_sw = dt;

        app_pq_ntt_enabled = 1;
        t0 = dwt_now();
        mlkem_polyvec_ntt(hw);
        dt = (dwt_now() - t0) / 3;
        if (dt < best_hw) best_hw = dt;
    }
    app_pq_ntt_enabled = 0;
    PRINTF("  NTT, software (Cortex-M33, portable C)     : %6lu cycles = %lu.%03lu ms\r\n", (unsigned long)best_sw,
           (unsigned long)(best_sw / 150000), (unsigned long)((best_sw / 150) % 1000));
    PRINTF("  NTT, PowerQuad (128 tiled block products)  : %6lu cycles = %lu.%03lu ms  -> %s by %lu.%02lux\r\n",
           (unsigned long)best_hw, (unsigned long)(best_hw / 150000), (unsigned long)((best_hw / 150) % 1000),
           best_hw < best_sw ? "FASTER" : "SLOWER",
           (unsigned long)(best_hw > best_sw ? best_hw / best_sw : best_sw / best_hw),
           (unsigned long)(best_hw > best_sw ? (best_hw * 100 / best_sw) % 100 : (best_sw * 100 / best_hw) % 100));

    /* Whole ML-KEM-768 operations, software NTT vs PowerQuad NTT (min of 10). */
    {
        extern int mlkem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
        extern int mlkem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
        extern int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
        uint8_t *pk = pvPortMalloc(1184), *sk = pvPortMalloc(2400), *ct = pvPortMalloc(1088);
        uint8_t ss[32], coins[64];
        if (pk && sk && ct)
        {
            volatile int rc = 0;
            psa_generate_random(coins, sizeof(coins));
            for (int mode = 0; mode < 2; mode++)
            {
                uint32_t best_kp = UINT32_MAX, best_dec = UINT32_MAX;
                app_pq_ntt_enabled = mode;
                for (int r = 0; r < 10; r++)
                {
                    uint32_t t0 = dwt_now();
                    rc |= mlkem_keypair_derand(pk, sk, coins);
                    uint32_t dt = dwt_now() - t0;
                    if (dt < best_kp) best_kp = dt;
                    rc |= mlkem_enc_derand(ct, ss, pk, coins);
                    t0 = dwt_now();
                    rc |= mlkem_dec(ss, ct, sk);
                    dt = dwt_now() - t0;
                    if (dt < best_dec) best_dec = dt;
                }
                PRINTF("  ML-KEM-768 keypair + decaps, NTT on %-9s: %7lu + %7lu cycles = %lu.%03lu ms%s\r\n",
                       mode ? "PowerQuad" : "CPU", (unsigned long)best_kp, (unsigned long)best_dec,
                       (unsigned long)((best_kp + best_dec) / 150000),
                       (unsigned long)(((best_kp + best_dec) / 150) % 1000), rc ? "  (ERROR)" : "");
            }
            app_pq_ntt_enabled = 0;
        }
        vPortFree(ct); vPortFree(sk); vPortFree(pk);
    }

    vPortFree(hw);
    vPortFree(sw);
}
