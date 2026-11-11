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

/* TLS 1.2 stays enabled in the port config so the client can still fall back;
 * app_mbedtls_socket.c pins the minimum version to TLS 1.3 so the benchmark is
 * unambiguous. */

#endif /* APP_MBEDTLS_USER_CONFIG_H */
