/*
 * FOCAL hackathon - precomputed hybrid key share. See app_keyshare.h.
 */

#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "fsl_debug_console.h"

#include "psa/crypto.h"
#include "mbedtls/platform_util.h"
#include "mlkem_native.h"

#include "app_keyshare.h"

volatile int app_keyshare_enabled = 0;

#define KEYSHARE_TASK_STACK_WORDS 5120 /* 20 KB; measured peak 14 040 B (run 20); 12 KB overflowed */
#define KEYSHARE_TASK_PRIO        2    /* below the client task (4) and the lwIP threads (3, 8) */

typedef struct
{
    uint8_t mlkem_pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t mlkem_sk[MLKEM768_SECRETKEYBYTES];
    uint8_t x25519_pk[32];
    mbedtls_svc_key_id_t x25519_key;
    int ready;
} keyshare_slot_t;

static keyshare_slot_t s_slot;
static SemaphoreHandle_t s_request; /* client -> helper: prepare one */
static SemaphoreHandle_t s_done;    /* helper -> client: finished */
static volatile int s_pending;      /* a request is outstanding */
static uint32_t s_generated, s_taken, s_fallbacks;
static TaskHandle_t s_task;

static int generate(keyshare_slot_t *s)
{
    uint8_t coins[2 * MLKEM_SYMBYTES];
    int rc;

    if (psa_generate_random(coins, sizeof(coins)) != PSA_SUCCESS) return -1;
    rc = mlkem_keypair_derand(s->mlkem_pk, s->mlkem_sk, coins);
    mbedtls_platform_zeroize(coins, sizeof(coins));
    if (rc != 0) return -1;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);
    s->x25519_key = MBEDTLS_SVC_KEY_ID_INIT;
    if (psa_generate_key(&attr, &s->x25519_key) != PSA_SUCCESS) return -1;

    size_t len = 0;
    if (psa_export_public_key(s->x25519_key, s->x25519_pk, sizeof(s->x25519_pk), &len) != PSA_SUCCESS || len != 32)
    {
        psa_destroy_key(s->x25519_key);
        s->x25519_key = MBEDTLS_SVC_KEY_ID_INIT;
        return -1;
    }
    return 0;
}

static void keyshare_task(void *arg)
{
    (void)arg;
    for (;;)
    {
        xSemaphoreTake(s_request, portMAX_DELAY);
        if (!s_slot.ready && generate(&s_slot) == 0)
        {
            s_slot.ready = 1;
            s_generated++;
        }
        xSemaphoreGive(s_done);
    }
}

int app_keyshare_init(void)
{
    s_request = xSemaphoreCreateBinary();
    s_done    = xSemaphoreCreateBinary();
    if (s_request == NULL || s_done == NULL) return -1;
    if (xTaskCreate(keyshare_task, "keyshare", KEYSHARE_TASK_STACK_WORDS, NULL, KEYSHARE_TASK_PRIO, &s_task) != pdPASS)
        return -1;
    return 0;
}

void app_keyshare_request(void)
{
    if (s_request == NULL || s_pending || s_slot.ready) return;
    s_pending = 1;
    xSemaphoreGive(s_request);
}

void app_keyshare_wait(void)
{
    if (!s_pending) return;
    if (xSemaphoreTake(s_done, pdMS_TO_TICKS(1000)) != pdTRUE) PRINTF("keyshare: helper task did not finish\r\n");
    s_pending = 0;
}

/* Hook called by the patched mbedTLS while it writes the ClientHello key_share. */
int mbedtls_ssl_tls13_hybrid_keyshare_take(unsigned char *mlkem_pk, unsigned char *mlkem_sk,
                                           unsigned char *x25519_pk, mbedtls_svc_key_id_t *x25519_key)
{
    if (!app_keyshare_enabled) return -1;
    app_keyshare_wait(); /* normally already done in the socket layer; harmless otherwise */
    if (!s_slot.ready)
    {
        s_fallbacks++;
        return -1;
    }
    memcpy(mlkem_pk, s_slot.mlkem_pk, sizeof(s_slot.mlkem_pk));
    memcpy(mlkem_sk, s_slot.mlkem_sk, sizeof(s_slot.mlkem_sk));
    memcpy(x25519_pk, s_slot.x25519_pk, sizeof(s_slot.x25519_pk));
    *x25519_key = s_slot.x25519_key; /* ownership moves to the handshake, which destroys it */

    mbedtls_platform_zeroize(s_slot.mlkem_sk, sizeof(s_slot.mlkem_sk));
    s_slot.x25519_key = MBEDTLS_SVC_KEY_ID_INIT;
    s_slot.ready      = 0;
    s_taken++;
    return 0;
}

void app_keyshare_stats(uint32_t *generated, uint32_t *taken, uint32_t *fallbacks, uint32_t *stack_used_bytes)
{
    *generated = s_generated;
    *taken     = s_taken;
    *fallbacks = s_fallbacks;
    *stack_used_bytes =
        s_task ? (KEYSHARE_TASK_STACK_WORDS - (uint32_t)uxTaskGetStackHighWaterMark2(s_task)) * sizeof(StackType_t) : 0;
}
