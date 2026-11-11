/*
 * FOCAL hackathon - mlkem-native arithmetic backend: forward NTT on the
 * MCXN947 PowerQuad matrix engine. Selected with
 *   -DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH -DMLK_CONFIG_ARITH_BACKEND_FILE="app_pq_ntt_backend.h"
 * Only the forward NTT is replaced; everything else stays mlkem-native's C.
 * The hook returns FALLBACK (= use the C NTT) unless app_pq_ntt_enabled is set,
 * so one firmware can benchmark both paths.
 */
#ifndef APP_PQ_NTT_BACKEND_H
#define APP_PQ_NTT_BACKEND_H

#define MLK_USE_NATIVE_NTT

#if !defined(__ASSEMBLER__)
#include "native/api.h" /* MLK_NATIVE_FUNC_SUCCESS / _FALLBACK, prototypes + contracts */

extern volatile int app_pq_ntt_enabled;
void app_pq_ntt(int16_t p[256]);

MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_ntt_native(int16_t data[MLKEM_N])
{
    if (!app_pq_ntt_enabled)
    {
        return MLK_NATIVE_FUNC_FALLBACK;
    }
    app_pq_ntt(data);
    return MLK_NATIVE_FUNC_SUCCESS;
}
#endif /* !__ASSEMBLER__ */

#endif /* APP_PQ_NTT_BACKEND_H */
