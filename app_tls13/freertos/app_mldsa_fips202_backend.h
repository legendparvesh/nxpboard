/*
 * FOCAL hackathon - step 6: mldsa-native FIPS-202 "native backend" used as an
 * abort hook.
 *
 * mldsa-native lets a backend replace the Keccak-f1600 permutation and fall
 * back to the C implementation by returning MLD_NATIVE_FUNC_FALLBACK. We do
 * not replace anything: the hook runs before every permutation (~0.1 ms apart
 * during signing) and, if the application says the current operation has
 * become pointless - the other core already produced a signature, or core 0
 * asked core 1 to stop - it longjmps out of the library. The application
 * resets the arena allocator afterwards (app_mld_arena.h).
 *
 * Selected via MLD_CONFIG_FIPS202_BACKEND_FILE in app_mldsa_config.h.
 */
#ifndef APP_MLDSA_FIPS202_BACKEND_H
#define APP_MLDSA_FIPS202_BACKEND_H

#define MLD_USE_NATIVE_FIPS202_X1

#if !defined(__ASSEMBLER__)
#include <stdint.h>

/* Values documented in mldsa/src/fips202/native/api.h */
#ifndef MLD_NATIVE_FUNC_SUCCESS
#define MLD_NATIVE_FUNC_SUCCESS (0)
#endif
#ifndef MLD_NATIVE_FUNC_FALLBACK
#define MLD_NATIVE_FUNC_FALLBACK (-1)
#endif

/* Provided by the application on each core. */
int app_mld_abort_poll(void);   /* non-zero: abandon the running mldsa call */
void app_mld_abort_jump(void);  /* longjmp back to the application (never returns) */

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_keccak_f1600_x1_native(uint64_t *state)
{
    (void)state;
    if (app_mld_abort_poll())
    {
        app_mld_abort_jump();
    }
    return MLD_NATIVE_FUNC_FALLBACK; /* always run the C permutation */
}
#endif /* !__ASSEMBLER__ */

#endif /* APP_MLDSA_FIPS202_BACKEND_H */
