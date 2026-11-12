/*
 * FOCAL hackathon - step 6: core 0 side of the dual-core crypto worker.
 *
 * Core 1 (app_core1/) is a bare-metal loop that signs with ML-DSA and
 * decapsulates ML-KEM on request. Core 0 uses it for
 *   - the ML-DSA signing race: both cores sign the same message with different
 *     randomness, the first valid signature wins, the other attempt is
 *     abandoned (app_hybrid_auth.c);
 *   - ML-KEM-768 decapsulation in parallel with the X25519 shared secret during
 *     the hybrid handshake (hooks called from the patched mbedTLS).
 * Built only when APP_DUALCORE=1 (Makefile: core 1 image embedded in flash at
 * 0x000C0000); otherwise every call is a no-op returning "not available".
 */
#ifndef APP_DUALCORE_H
#define APP_DUALCORE_H

#include <stddef.h>
#include <stdint.h>

#include "app_dualcore_shm.h"

/* Runtime switch, set per benchmark arm. */
extern volatile int app_dualcore_enabled;

typedef struct
{
    uint32_t sign_core0_wins;  /* core 0's own signature used */
    uint32_t sign_core1_wins;  /* core 1 finished first, core 0's attempt abandoned */
    uint32_t sign_both_done;   /* core 1 finished in the window between core 0 finishing and the abort */
    uint32_t sign_aborted;     /* core 1 attempt abandoned on request */
    uint32_t sign_core1_err;   /* core 1 failed/timed out, signed on core 0 alone */
    uint32_t dec_offloaded;    /* ML-KEM decapsulations done on core 1 */
    uint32_t dec_fallbacks;    /* ... that had to be redone on core 0 */
    uint32_t core1_sign_cycles_last;
    uint32_t core1_arena_peak;
} app_dualcore_stats_t;

extern app_dualcore_stats_t app_dualcore_stats;

/* Boot core 1 and run a ping. 0 on success (core 1 ready), -1 otherwise. */
int app_dualcore_start(void);
int app_dualcore_ready(void);

/* Low-level command interface (one command in flight at a time). */
volatile app_dualcore_shm_t *app_dualcore_shm(void);
int app_dualcore_cmd(uint32_t cmd);          /* 0 = sent */
int app_dualcore_done(void);                 /* non-zero once core 1 has reported a final status */
int app_dualcore_wait(uint32_t timeout_ms);  /* final status (APP_DC_*), or -1 none pending, -2 timeout */
void app_dualcore_abort(void);               /* ask core 1 to abandon the command in flight */

#endif /* APP_DUALCORE_H */
