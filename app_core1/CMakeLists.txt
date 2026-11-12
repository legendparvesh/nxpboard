# FOCAL hackathon - core 1 crypto worker (see main.c). Built by `make build-core1`
# into sdk/mcuxsdk/build_core1/core1_image.bin, which the core 0 build embeds.
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.22.0)

include(${SdkRootDirPath}/cmake/extension/mcux.cmake)

project(focal_core1
        LANGUAGES C CXX ASM
        PROJECT_BOARD_PORT_PATH ${board_root}/${board}/focal_core1)

include(${SdkRootDirPath}/CMakeLists.txt)

mcux_add_source(
    BASE_PATH ${SdkRootDirPath}
    SOURCES examples/focal_core1/main.c
            # shared with core 0 (examples/focal_challenge -> app_tls13)
            examples/focal_challenge/freertos/app_dualcore_shm.h
            examples/focal_challenge/freertos/app_mld_arena.h
            examples/focal_challenge/freertos/app_mld_arena.c
            examples/focal_challenge/freertos/app_mldsa_config.h
            examples/focal_challenge/freertos/app_mldsa_fips202_backend.h
            # ML-KEM-768 / ML-DSA-44, portable C
            examples/focal_third_party/mlkem-native/mlkem/mlkem_native.c
            examples/focal_third_party/mldsa-native/mldsa/mldsa_native.c
)

mcux_add_include(
    BASE_PATH ${SdkRootDirPath}
    INCLUDES examples/focal_core1
             examples/focal_challenge/freertos
             examples/focal_third_party/mlkem-native/mlkem
             examples/focal_third_party/mlkem-native/mlkem/src
             examples/focal_third_party/mldsa-native/mldsa
)

mcux_add_macro(
    CC "-DAPP_CORE1=1\
        -DMCMGR_BUSY_POLL_COUNT=200000\
        -DMLD_CONFIG_FILE=\\\"app_mldsa_config.h\\\"\
        -DMLK_CONFIG_PARAMETER_SET=768\
        -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem\
        -DMLK_CONFIG_NO_RANDOMIZED_API"
)

# Run in place from flash (m_core1_image, 0x000C0000) with the full 104 KB of
# core 1 RAM for data: the default core 1 "ram" layout has only 52 KB of data,
# too small for ML-DSA signing. 24 KB stack, no heap (arena is static).
mcux_remove_armgcc_linker_script(
    TARGETS debug release
    BASE_PATH ${SdkRootDirPath}
    LINKER ${device_root}/${soc_portfolio}/${soc_series}/${device}/gcc/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_ram.ld
)
mcux_add_armgcc_linker_script(
    TARGETS debug release
    BASE_PATH ${SdkRootDirPath}
    LINKER ${device_root}/${soc_portfolio}/${soc_series}/${device}/gcc/${CONFIG_MCUX_TOOLCHAIN_LINKER_DEVICE_PREFIX}_flash.ld
)
mcux_add_linker_symbol(
    SYMBOLS "__stack_size__=0x6000\
             __heap_size__=0x0"
)

include(${SdkRootDirPath}/${board_root}/${board}/focal_core1/reconfig.cmake OPTIONAL)

mcux_convert_binary(
    TOOLCHAINS armgcc
    BINARY ${APPLICATION_BINARY_DIR}/core1_image.bin
)
