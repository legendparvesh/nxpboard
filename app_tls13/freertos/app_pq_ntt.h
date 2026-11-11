/*
 * FOCAL hackathon - ML-KEM NTT on the MCXN947 PowerQuad matrix engine.
 *
 * The ML-KEM NTT (FIPS 203 Alg. 9) is two 128x128 matrix-vector products with
 * the twiddle matrix W[i][j] = 17^((2*BitRev7(i)+1)*j) mod q (even and odd
 * coefficients share W). The PowerQuad matrix engine multiplies operands of at
 * most 16x16 and computes in float32 internally, so:
 *   - W and the input are split into 6-bit limbs (x = hi*64 + lo) so that every
 *     16-term dot product (<= 63*63*16) is exact in float32;
 *   - W is stored tile-major as 8x8 tiles of 16x16 (app_pq_ntt_tables.c);
 *   - the engine computes one 16x16 * 16x4 block product per call
 *     (B columns: even_lo, even_hi, odd_lo, odd_hi), the CPU accumulates the
 *     8 column tiles, recombines the limbs and reduces mod q.
 * Plugged into mlkem-native through MLK_USE_NATIVE_NTT (app_pq_ntt_backend.h),
 * so the real TLS handshake runs its NTTs on the accelerator when
 * app_pq_ntt_enabled != 0.
 */
#ifndef APP_PQ_NTT_H
#define APP_PQ_NTT_H

#include <stdint.h>

/* Runtime switch read by the mlkem-native backend hook: 0 = software NTT, 1 = PowerQuad. */
extern volatile int app_pq_ntt_enabled;

/* Enable clock, configure the matrix engine (int16 inputs, int32 output). */
void app_pq_ntt_init(void);

/* In-place NTT of one polynomial (normal order in, bit-reversed order out,
 * coefficients reduced to [0, q)). Input must be bounded by q in absolute value. */
void app_pq_ntt(int16_t p[256]);

/* Self-test against the software NTT and cycle-count benchmark; prints a table. */
void app_pq_ntt_bench(void);

#endif /* APP_PQ_NTT_H */
