/*
 * FOCAL hackathon - mldsa-native configuration for the FRDM-MCXN947.
 *
 * Selected via -DMLD_CONFIG_FILE="app_mldsa_config.h" (CMakeLists.txt). Sets
 * our options, then pulls in the library's default config for everything else.
 */
#ifndef APP_MLDSA_CONFIG_H
#define APP_MLDSA_CONFIG_H

/* 65 = NIST cat. 3 (matches RSA-3072 / AES-128); 44 = cat. 2, ~2x faster signing, 2420 B sig. */
#define MLD_CONFIG_PARAMETER_SET 44

/* Symbols become mldsa_keypair_internal, mldsa_signature_internal, mldsa_verify, ... */
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa

/* Deterministic API only (we pass seeds / rnd from mbedTLS's DRBG ourselves),
 * so no global randombytes() is required. */
#define MLD_CONFIG_NO_RANDOMIZED_API

/* Trade a little speed for a lot less working memory. */
#define MLD_CONFIG_REDUCE_RAM

/* ML-DSA-65 keeps up to ~68 KB (sign) / ~40 KB (verify) of polynomial vectors
 * in working memory. That cannot live on a FreeRTOS task stack, so route the
 * large allocations to the FreeRTOS heap (see app_hybrid_auth.c). */
#define MLD_CONFIG_CUSTOM_ALLOC_FREE
#if !defined(__ASSEMBLER__)
#include <stddef.h>
void *app_mld_aligned_alloc(size_t size);
void app_mld_aligned_free(void *p);
#define MLD_CUSTOM_ALLOC(v, T, N) T *(v) = (T *)app_mld_aligned_alloc(MLD_ALIGN_UP(sizeof(T) * (N)))
#define MLD_CUSTOM_FREE(v, T, N) app_mld_aligned_free(v)
#endif

/* Everything else: library defaults. */
/* Step 6 (dual core): hook every Keccak permutation so a signing attempt can be
 * abandoned once the other core has produced a signature (app_mldsa_fips202_backend.h). */
#define MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLD_CONFIG_FIPS202_BACKEND_FILE "app_mldsa_fips202_backend.h"

#include "mldsa_native_config.h"

#endif /* APP_MLDSA_CONFIG_H */
