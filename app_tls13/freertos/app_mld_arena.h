/*
 * FOCAL hackathon - bump arena for mldsa-native's working buffers.
 *
 * mldsa-native (MLD_CONFIG_CUSTOM_ALLOC_FREE) allocates its polynomial vectors
 * at the start of an API call and frees them at the end. A bump arena with a
 * last-in-first-out free is enough for that pattern, and it has the property
 * the dual-core signing race needs: when a signing attempt is abandoned with
 * longjmp, everything it allocated is reclaimed and wiped by one reset.
 * Provides app_mld_aligned_alloc / app_mld_aligned_free (see app_mldsa_config.h).
 */
#ifndef APP_MLD_ARENA_H
#define APP_MLD_ARENA_H

#include <stddef.h>
#include <stdint.h>

#ifndef APP_MLD_ARENA_BYTES
#define APP_MLD_ARENA_BYTES (32u * 1024u) /* ML-DSA-44 (REDUCE_RAM): measured peak ~18 KB on core 1 */
#endif

void app_mld_arena_init(void *buf, size_t size); /* buf need not be aligned */
void app_mld_arena_reset(int zeroize);           /* drop everything; wipe the used part if zeroize */
size_t app_mld_arena_peak(void);                 /* high-water mark, bytes */
size_t app_mld_arena_in_use(void);

void *app_mld_aligned_alloc(size_t size);
void app_mld_aligned_free(void *p);

#endif /* APP_MLD_ARENA_H */
