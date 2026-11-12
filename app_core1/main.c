/*
 * FOCAL hackathon - step 6: core 1 crypto worker (bare metal, no RTOS).
 *
 * Runs in place from flash at 0x000C0000 (embedded in the core 0 image). Core 0
 * starts it through the multicore manager and passes the address of the shared
 * command block (app_dualcore_shm.h) as the startup word. The loop sleeps in
 * WFI until the mailbox interrupt delivers a command, executes it, and reports
 * the final status back through the mailbox.
 *
 * Commands: PING, ML-DSA signature (abortable: core 0 can tell us to stop and we
 * longjmp out of the library from the Keccak hook), ML-KEM-768 decapsulation.
 */
#include <setjmp.h>
#include <string.h>

#include "fsl_common.h"
#include "fsl_device_registers.h"
#include "board.h"
#include "app.h"
#include "mcmgr.h"

#include "mldsa_native.h"
#include "app_dualcore_shm.h"
#include "app_mld_arena.h"

extern int mlkem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define SIG_BYTES MLDSA_BYTES(MLD_CONFIG_PARAMETER_SET)

static volatile app_dualcore_shm_t *shm;
static volatile uint32_t s_cmd;   /* set by the mailbox ISR */
static volatile uint32_t s_abort; /* set by the mailbox ISR */
static jmp_buf s_jmp;
static volatile int s_jmp_armed;
static uint8_t s_arena[APP_MLD_ARENA_BYTES + 64] __attribute__((aligned(64)));

static void on_cmd(mcmgr_core_t core, uint16_t data, void *ctx)
{
    (void)core;
    (void)ctx;
    s_cmd = data;
}

static void on_abort(mcmgr_core_t core, uint16_t data, void *ctx)
{
    (void)core;
    (void)data;
    (void)ctx;
    s_abort = 1;
}

/* Keccak hook (app_mldsa_fips202_backend.h) */
int app_mld_abort_poll(void)
{
    return s_jmp_armed && (s_abort || shm->abort);
}

void app_mld_abort_jump(void)
{
    longjmp(s_jmp, 1);
}

static inline uint32_t cyc(void)
{
    return DWT->CYCCNT;
}

static void report(uint32_t status, uint32_t t0)
{
    shm->cycles     = cyc() - t0;
    shm->arena_peak = app_mld_arena_peak();
    shm->status     = status;
    __DSB();
    (void)MCMGR_TriggerEvent(kMCMGR_Core0, kMCMGR_RemoteApplicationEvent, (uint16_t)status);
}

int main(void)
{
    uint32_t startup = 0;

    BOARD_InitHardware();
    (void)MCMGR_Init();

    /* Core 0 passes the shared block's address as the startup word. */
    while (MCMGR_GetStartupData(kMCMGR_Core0, &startup) != kStatus_MCMGR_Success)
    {
    }
    shm = (volatile app_dualcore_shm_t *)startup;

    (void)MCMGR_RegisterEvent(kMCMGR_RemoteApplicationEvent, on_cmd, NULL);
    (void)MCMGR_RegisterEvent(kMCMGR_RemoteApplicationEvent1, on_abort, NULL);

    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    app_mld_arena_init(s_arena, sizeof(s_arena));

    shm->sysclk_hz = SystemCoreClock;
    shm->magic     = APP_DC_MAGIC;
    __DSB();

    for (;;)
    {
        while (s_cmd == 0)
        {
            __WFI();
        }
        const uint32_t cmd = s_cmd;
        s_cmd              = 0;
        s_abort            = 0;
        const uint32_t t0  = cyc();

        switch (cmd)
        {
            case APP_DC_CMD_PING:
                shm->pong = shm->ping + 1u;
                report(APP_DC_DONE, t0);
                break;

            case APP_DC_CMD_SIGN:
                app_mld_arena_reset(0);
                s_jmp_armed = 1;
                if (setjmp(s_jmp) == 0)
                {
                    int rc = mldsa_signature_internal((uint8_t *)shm->sig, (const uint8_t *)shm->msg, shm->msg_len,
                                                      (const uint8_t *)shm->pre, shm->pre_len,
                                                      (const uint8_t *)shm->rnd, (const uint8_t *)shm->sk, 0);
                    s_jmp_armed  = 0;
                    shm->sig_len = (rc == 0) ? SIG_BYTES : 0u;
                    report((rc == 0) ? APP_DC_DONE : APP_DC_ERROR, t0);
                }
                else
                {
                    /* abandoned on core 0's request: wipe the half-finished attempt */
                    s_jmp_armed = 0;
                    app_mld_arena_reset(1);
                    shm->sig_len = 0;
                    report(APP_DC_ABORTED, t0);
                }
                break;

            case APP_DC_CMD_MLKEM_DEC:
            {
                int rc = mlkem_dec((uint8_t *)shm->ss, (const uint8_t *)shm->ct, (const uint8_t *)shm->kem_sk);
                report((rc == 0) ? APP_DC_DONE : APP_DC_ERROR, t0);
                break;
            }

            default:
                report(APP_DC_ERROR, t0);
                break;
        }
    }
}
