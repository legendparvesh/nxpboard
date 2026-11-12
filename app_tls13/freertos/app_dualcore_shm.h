/*
 * FOCAL hackathon - step 6: dual-core. Shared command block between core 0
 * (FreeRTOS TLS client) and core 1 (bare-metal crypto worker, app_core1/).
 *
 * The block lives in core 0's RAM; its address is handed to core 1 as the
 * multicore-manager startup word. Both cores see the same SRAM (no data cache
 * on this part), so pointers to core 0 buffers are valid on core 1 as they are.
 * Signalling goes through the mailbox (MCMGR remote-application events):
 *   core 0 -> core 1  kMCMGR_RemoteApplicationEvent  = command id
 *   core 0 -> core 1  kMCMGR_RemoteApplicationEvent1 = abort the running command
 *   core 1 -> core 0  kMCMGR_RemoteApplicationEvent  = final status
 */
#ifndef APP_DUALCORE_SHM_H
#define APP_DUALCORE_SHM_H

#include <stdint.h>

#define APP_DC_MAGIC   0x50514331u /* "PQC1": written by core 1 once it is parked and listening */
#define APP_DC_SIG_MAX 3309u       /* ML-DSA-65 signature; ML-DSA-44 uses 2420 of it */

/* Commands (sent as the 16-bit event payload and mirrored in `cmd`). */
enum
{
    APP_DC_CMD_NONE      = 0,
    APP_DC_CMD_PING      = 1, /* pong = ping + 1 */
    APP_DC_CMD_SIGN      = 2, /* ML-DSA signature of msg with rnd -> sig */
    APP_DC_CMD_MLKEM_DEC = 3, /* ML-KEM-768 decapsulation of ct with kem_sk -> ss */
};

/* Status of the last/current command. */
enum
{
    APP_DC_IDLE    = 0,
    APP_DC_BUSY    = 1,
    APP_DC_DONE    = 2,
    APP_DC_ABORTED = 3,
    APP_DC_ERROR   = 4,
};

typedef struct
{
    uint32_t magic;
    uint32_t cmd;
    uint32_t status;
    uint32_t abort;     /* core 0 sets 1 to abandon the running command */
    uint32_t ping, pong;
    uint32_t cycles;    /* core 1 DWT cycles spent on the last command */
    uint32_t sysclk_hz; /* core 1's SystemCoreClock, for the record */
    uint32_t arena_peak;/* core 1's peak ML-DSA working memory, bytes */

    /* ML-DSA signing (all pointers into core 0 memory) */
    const uint8_t *msg;
    uint32_t msg_len;
    const uint8_t *pre; /* domain-separation prefix */
    uint32_t pre_len;
    const uint8_t *sk;
    uint8_t rnd[32];
    uint8_t sig[APP_DC_SIG_MAX];
    uint32_t sig_len;

    /* ML-KEM-768 decapsulation */
    const uint8_t *ct;
    const uint8_t *kem_sk;
    uint8_t ss[32];
} app_dualcore_shm_t;

#endif /* APP_DUALCORE_SHM_H */
