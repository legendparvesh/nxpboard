/*
 * FOCAL hackathon - step 6: core 0 side of the dual-core crypto worker. See app_dualcore.h.
 */
#include <string.h>

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#include "fsl_debug_console.h"
#include "fsl_device_registers.h"

#include "app_dualcore.h"

volatile int app_dualcore_enabled    = 0;
app_dualcore_stats_t app_dualcore_stats = {0};

#if APP_DUALCORE

#include "mcmgr.h"

#define APP_CORE1_BOOT_ADDRESS 0x000C0000u /* m_core1_image in the core 0 linker script; core 1 runs in place */

static app_dualcore_shm_t s_shm __attribute__((aligned(32)));
static volatile app_dualcore_shm_t *const shm = &s_shm;

static SemaphoreHandle_t s_done_sem;
static volatile uint32_t s_done_flag;   /* core 1 reported a final status for the command in flight */
static volatile uint16_t s_last_status; /* ... which was */
static volatile uint32_t s_pending;     /* command in flight (0 = none) */
static int s_ready;

/* Runs in the MAILBOX ISR (priority 5 >= configMAX_SYSCALL_INTERRUPT_PRIORITY). */
static void on_core1_event(mcmgr_core_t core, uint16_t data, void *ctx)
{
    (void)core;
    (void)ctx;
    s_last_status = data;
    s_done_flag   = 1;
    if (s_done_sem != NULL)
    {
        BaseType_t woken = pdFALSE;
        xSemaphoreGiveFromISR(s_done_sem, &woken);
        portYIELD_FROM_ISR(woken);
    }
}

volatile app_dualcore_shm_t *app_dualcore_shm(void)
{
    return shm;
}

int app_dualcore_ready(void)
{
    return s_ready;
}

int app_dualcore_done(void)
{
    return (int)s_done_flag;
}

int app_dualcore_cmd(uint32_t cmd)
{
    if (!s_ready || s_pending != 0)
    {
        return -1;
    }
    s_done_flag = 0;
    (void)xSemaphoreTake(s_done_sem, 0); /* drain a stale give */
    shm->cmd    = cmd;
    shm->abort  = 0;
    shm->status = APP_DC_BUSY;
    __DSB();
    if (MCMGR_TriggerEvent(kMCMGR_Core1, kMCMGR_RemoteApplicationEvent, (uint16_t)cmd) != kStatus_MCMGR_Success)
    {
        shm->status = APP_DC_IDLE;
        return -1;
    }
    s_pending = cmd;
    return 0;
}

int app_dualcore_wait(uint32_t timeout_ms)
{
    if (s_pending == 0)
    {
        return -1;
    }
    int ok = s_done_flag || (xSemaphoreTake(s_done_sem, pdMS_TO_TICKS(timeout_ms)) == pdTRUE);
    s_pending = 0;
    __DSB();
    if (!ok)
    {
        return -2;
    }
    return (int)shm->status;
}

void app_dualcore_abort(void)
{
    if (s_pending == 0)
    {
        return;
    }
    shm->abort = 1;
    __DSB();
    (void)MCMGR_TriggerEvent(kMCMGR_Core1, kMCMGR_RemoteApplicationEvent1, 0);
}

int app_dualcore_start(void)
{
    s_done_sem = xSemaphoreCreateBinary();
    if (s_done_sem == NULL)
    {
        return -1;
    }
    (void)MCMGR_RegisterEvent(kMCMGR_RemoteApplicationEvent, on_core1_event, NULL);

    memset(&s_shm, 0, sizeof(s_shm));
    __DSB();

    PRINTF("\r\n=== Dual core: starting core 1 (image at 0x%08lx, shared block at 0x%08lx) ===\r\n",
           (unsigned long)APP_CORE1_BOOT_ADDRESS, (unsigned long)(uintptr_t)&s_shm);
    if (MCMGR_StartCore(kMCMGR_Core1, (void *)APP_CORE1_BOOT_ADDRESS, (uint32_t)(uintptr_t)&s_shm,
                        kMCMGR_Start_Synchronous) != kStatus_MCMGR_Success)
    {
        PRINTF("  core 1 did not start\r\n");
        return -1;
    }
    for (int i = 0; i < 500 && shm->magic != APP_DC_MAGIC; i++)
    {
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    if (shm->magic != APP_DC_MAGIC)
    {
        PRINTF("  core 1 started but never reported ready\r\n");
        return -1;
    }
    s_ready = 1;

    /* Ping: round trip through both mailboxes. */
    shm->ping = 0x1234u;
    TickType_t t0 = xTaskGetTickCount();
    if (app_dualcore_cmd(APP_DC_CMD_PING) != 0 || app_dualcore_wait(100) != APP_DC_DONE || shm->pong != 0x1235u)
    {
        PRINTF("  ping failed (status %lu, pong 0x%lx)\r\n", (unsigned long)shm->status, (unsigned long)shm->pong);
        s_ready = 0;
        return -1;
    }
    PRINTF("  core 1 ready: ping ok in %lu ms, core 1 clock %lu MHz\r\n",
           (unsigned long)((xTaskGetTickCount() - t0) * portTICK_PERIOD_MS), (unsigned long)(shm->sysclk_hz / 1000000u));
    return 0;
}

/* ---- hooks called from the patched mbedTLS (ssl_tls13_keys.c) ---------- */
static volatile int s_dec_pending;

int mbedtls_ssl_tls13_hybrid_mlkem_dec_begin(const unsigned char *ct, const unsigned char *sk)
{
    if (!app_dualcore_enabled || !s_ready)
    {
        return -1;
    }
    shm->ct     = ct;
    shm->kem_sk = sk;
    if (app_dualcore_cmd(APP_DC_CMD_MLKEM_DEC) != 0)
    {
        return -1;
    }
    s_dec_pending = 1;
    return 0;
}

int mbedtls_ssl_tls13_hybrid_mlkem_dec_end(unsigned char *ss)
{
    if (!s_dec_pending)
    {
        return -1;
    }
    s_dec_pending = 0;
    int st = app_dualcore_wait(100);
    if (st != APP_DC_DONE)
    {
        app_dualcore_stats.dec_fallbacks++;
        return -1;
    }
    memcpy(ss, (const void *)shm->ss, 32);
    for (int i = 0; i < 32; i++) shm->ss[i] = 0;
    app_dualcore_stats.dec_offloaded++;
    return 0;
}

#else /* !APP_DUALCORE: single-core build, everything unavailable */

static app_dualcore_shm_t s_shm;
volatile app_dualcore_shm_t *app_dualcore_shm(void) { return &s_shm; }
int app_dualcore_start(void) { return -1; }
int app_dualcore_ready(void) { return 0; }
int app_dualcore_cmd(uint32_t cmd) { (void)cmd; return -1; }
int app_dualcore_done(void) { return 0; }
int app_dualcore_wait(uint32_t timeout_ms) { (void)timeout_ms; return -1; }
void app_dualcore_abort(void) {}
int mbedtls_ssl_tls13_hybrid_mlkem_dec_begin(const unsigned char *ct, const unsigned char *sk) { (void)ct; (void)sk; return -1; }
int mbedtls_ssl_tls13_hybrid_mlkem_dec_end(unsigned char *ss) { (void)ss; return -1; }

#endif /* APP_DUALCORE */
