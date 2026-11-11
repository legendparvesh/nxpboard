# Adapted from NXP MCUXpresso SDK lwip_https_client_freertos example.
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.22.0)

include(${SdkRootDirPath}/cmake/extension/mcux.cmake)

project(focal_handshake_challenge
        LANGUAGES C CXX ASM
        PROJECT_BOARD_PORT_PATH ${board_root}/${board}/focal_challenge/freertos)

include(${SdkRootDirPath}/CMakeLists.txt)

mcux_add_source(
    BASE_PATH ${SdkRootDirPath}
    SOURCES examples/focal_challenge/freertos/main.c
            examples/focal_challenge/freertos/app_ca_bundle.h
            examples/focal_challenge/freertos/app_ca_bundle.c
            examples/focal_challenge/freertos/app_corehttp.h
            examples/focal_challenge/freertos/app_corehttp.c
            examples/focal_challenge/freertos/app_mbedtls_socket.h
            examples/focal_challenge/freertos/app_mbedtls_socket.c
            examples/focal_challenge/freertos/app_https_client_task.h
            examples/focal_challenge/freertos/app_https_client_task.c
            examples/focal_challenge/freertos/core_http_config.h
            examples/focal_challenge/freertos/app_mbedtls_user_config.h
            # ML-KEM-768 (mlkem-native, single-compilation-unit build) for X25519MLKEM768.
            # focal_third_party -> ../../../third_party (symlink made by `make graft`).
            examples/focal_third_party/mlkem-native/mlkem/mlkem_native.c
)

mcux_add_include(
    BASE_PATH ${SdkRootDirPath}
    INCLUDES examples/focal_challenge/freertos
             examples/focal_third_party/mlkem-native/mlkem
)

# mlkem-native configuration: ML-KEM-768 only, portable C (no asm backend on
# Cortex-M33), deterministic API only so no global randombytes() is needed —
# the TLS layer feeds it coins from mbedTLS's own RNG.
mcux_add_macro(
    CC "-DMLK_CONFIG_PARAMETER_SET=768\
        -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem\
        -DMLK_CONFIG_NO_RANDOMIZED_API"
)

# MBEDTLS_USER_CONFIG_FILE is appended to the NXP port config by the SDK, so
# TLS 1.3 can be switched on here without editing anything under sdk/.
# (Escaping follows the SDK's own el2go examples.)
mcux_add_macro(
    CC "-DUSE_RTOS=1\
        -DPRINTF_ADVANCED_ENABLE=1\
        -DMBEDTLS_ERROR_C\
        -DMBEDTLS_USER_CONFIG_FILE=\\\"app_mbedtls_user_config.h\\\"\
        -DAPP_DRBG_SEED_ONCE=1"
)

mcux_add_macro(
    TOOLCHAINS armgcc
    CC "-D_POSIX_SOURCE"
)

mcux_add_linker_symbol(
    SYMBOLS "__stack_size__=0x400\
             __heap_size__=0x18000"
)

include(${SdkRootDirPath}/${board_root}/${board}/focal_challenge/freertos/reconfig.cmake OPTIONAL)

mcux_convert_binary(BINARY ${APPLICATION_BINARY_DIR}/${MCUX_SDK_PROJECT_NAME}.bin)
