/*
 * FOCAL hackathon - step 2: enable TLS 1.3 on top of the NXP mbedTLS 3.6 port.
 *
 * This file is pulled in at the very end of the SDK's mcux_mbedtls_config.h via
 * MBEDTLS_USER_CONFIG_FILE (set in CMakeLists.txt), so it can add to or undo
 * anything the port config defines without modifying files under sdk/.
 */

#ifndef APP_MBEDTLS_USER_CONFIG_H
#define APP_MBEDTLS_USER_CONFIG_H

/* --- TLS 1.3 ------------------------------------------------------------- */

/* The NXP port leaves this commented out ("// NXP"). Everything TLS 1.3 needs
 * (MBEDTLS_PSA_CRYPTO_C, MBEDTLS_USE_PSA_CRYPTO, HKDF, the TLS1_3 key-exchange
 * mode flags, X25519 / P-256, RSA-PSS) is already enabled in the port config. */
#define MBEDTLS_SSL_PROTO_TLS1_3

/* Send/accept the dummy ChangeCipherSpec records that "middlebox compatible"
 * TLS 1.3 stacks (OpenSSL servers by default) emit. */
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE

/* TLS 1.2 stays enabled in the port config so the A/B benchmark can pin either
 * version per connection (see app_mbedtls_socket.c). */

/* --- Step 3: hybrid key exchange X25519MLKEM768 --------------------------- */

/* Enables the FOCAL patch in the SDK's mbedTLS (patches/mbedtls3x-x25519mlkem768.patch):
 * named group 0x11EC, ML-KEM-768 half provided by mlkem-native (third_party/).
 * The group is only used if the application puts it in mbedtls_ssl_conf_groups(). */
#define MBEDTLS_SSL_TLS1_3_HYBRID_MLKEM

/* Step 5: let the application hand mbedTLS a hybrid key share it prepared while
 * the TCP connect was in flight (app_keyshare.c). Falls back to inline
 * generation when none is ready. */
#define MBEDTLS_SSL_TLS1_3_HYBRID_MLKEM_PRECOMPUTED

/* --- Step 4: hybrid authentication ------------------------------------------ */

/* RFC 5705/8446 exporter: the device signs a value derived from the live TLS
 * session, so its ML-DSA + ECDSA signatures are bound to this connection. */
#define MBEDTLS_SSL_KEYING_MATERIAL_EXPORT

#endif /* APP_MBEDTLS_USER_CONFIG_H */
