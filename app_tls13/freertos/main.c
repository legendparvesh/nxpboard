/*
 * Copyright 2016-2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/

#include "lwip/opt.h"

#if LWIP_SOCKET
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>

#include "FreeRTOS.h"
#include "task.h"

#include "app_https_client_task.h"
#include "ethernetif.h"
#include "board.h"
#include "app.h"
#include "fsl_phy.h"

#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/arch.h"
#include "lwip/dns.h"
#include "lwip/api.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "lwip/ip.h"
#include "psa/crypto.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* Must be after include of app.h */
#ifndef configMAC_ADDR
#include "fsl_silicon_id.h"
#endif

#ifndef EXAMPLE_HOST
/*! @brief FOCAL hackathon challenge server (IPv4 literal, provided by the organisers).
 *  The IPv6 literal "2a0f:7cc7:7cc7:7c40::94ad" also works on an IPv6-capable network;
 *  set EXAMPLE_HOST_IS_IPV6 to 1 when using it so the SLAAC wait is re-enabled. */
#define EXAMPLE_HOST "193.30.40.242"
#endif /* EXAMPLE_HOST */

#ifndef EXAMPLE_HOST_IS_IPV6
/*! @brief 1 if EXAMPLE_HOST is an IPv6 literal (wait for SLAAC), 0 for IPv4 (wait for DHCP). */
#define EXAMPLE_HOST_IS_IPV6 0
#endif /* EXAMPLE_HOST_IS_IPV6 */

#ifndef EXAMPLE_DHCP_TIMEOUT_MS
/*! @brief How long to wait for a DHCPv4 lease before giving up. */
#define EXAMPLE_DHCP_TIMEOUT_MS 15000
#endif /* EXAMPLE_DHCP_TIMEOUT_MS */

#ifndef EXAMPLE_PORT
/*! @brief HTTPS port of the challenge server. */
#define EXAMPLE_PORT 443
#endif /* EXAMPLE_PORT */

#ifndef EXAMPLE_PATH
/*! @brief Request path echoed back to the student in the JSON response. */
#define EXAMPLE_PATH "/frdm-mcxn947"
#endif /* EXAMPLE_PATH */

#ifndef EXAMPLE_ITERATIONS
/*! @brief Number of full connect + TLS handshake + GET rounds to benchmark. */
#define EXAMPLE_ITERATIONS 100
#endif /* EXAMPLE_ITERATIONS */

#ifndef EXAMPLE_TLS_MODE
/*! @brief Benchmark arms, interleaved round by round (see app_https_client_task.h):
 *  0 = TLS1.3 vs TLS1.2, 2 = TLS1.2, 3 = TLS1.3, 4 = hybrid vs TLS1.3,
 *  5 = hybrid only, 6 = hybrid vs TLS1.3 vs TLS1.2, 9 = five-arm headline,
 *  10 = PowerQuad NTT vs CPU NTT (KEX only), 11 = deployment config (hybrid KEX + ML-DSA-44/ECDSA
 *  sign-only auth) with ML-KEM NTT on CPU vs on the PowerQuad (two arms), 12 = deployment config
 *  with the hybrid key share precomputed during the TCP connect vs inline (two arms),
 *  13 = deployment config + precompute, with core 1 (ML-DSA signing race + ML-KEM decaps
 *  offload) vs single core (two arms). */
#define EXAMPLE_TLS_MODE 13
#endif /* EXAMPLE_TLS_MODE */

#ifndef EXAMPLE_MAX_REQUEST_LENGTH
/*! @brief Maximum length of HTTP request. The hybrid-auth header carries a
 *  base64 ML-DSA-65 signature (3309 B -> 4412 chars) plus ECDSA, so ~5 KB. */
#define EXAMPLE_MAX_REQUEST_LENGTH 6144
#endif /* EXAMPLE_MAX_REQUEST_LENGTH */

#ifndef EXAMPLE_MAX_RESPONSE_LENGTH
/*! @brief Maximum length of HTTP response. */
#define EXAMPLE_MAX_RESPONSE_LENGTH 1024
#endif /* EXAMPLE_MAX_RESPONSE_LENGTH */

#ifndef EXAMPLE_NETIF_INIT_FN
/*! @brief Network interface initialization function. */
#define EXAMPLE_NETIF_INIT_FN ethernetif0_init
#endif /* EXAMPLE_NETIF_INIT_FN */

#ifndef INIT_THREAD_STACKSIZE
/*! @brief Stack size of the temporary initialization thread in words. */
#define INIT_THREAD_STACKSIZE 1024
#endif /* INIT_THREAD_STACKSIZE */

#ifndef INIT_THREAD_PRIO
/*! @brief Priority of the temporary initialization thread. */
#define INIT_THREAD_PRIO DEFAULT_THREAD_PRIO
#endif /* INIT_THREAD_PRIO */

#ifndef HTTPS_CLIENT_THREAD_STACKSIZE
/*! @brief Stack size of the HTTPS client thread in words. */
/* Words (4 B). 16 KB was enough for classical TLS; ML-KEM-768 keygen/decaps keep
 * ~8-10 KB of polynomial vectors on the stack on top of the handshake, so 32 KB. */
#define HTTPS_CLIENT_THREAD_STACKSIZE 8192
#endif

#ifndef HTTPS_CLIENT_THREAD_PRIO
/*! @brief Priority of the HTTPS client thread. */
#define HTTPS_CLIENT_THREAD_PRIO (configMAX_PRIORITIES - 14U)
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

#if LWIP_IPV6
static void print_ipv6_addresses(struct netif *netif);
static void netif_ipv6_callback(struct netif *cb_netif);
#endif /* LWIP_IPV6 */

static void init_task(void *arg);
static void init_task_init(void);

/*******************************************************************************
 * Variables
 ******************************************************************************/

static phy_handle_t phyHandle;
static struct netif netif;

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Main function.
 */
/*!
 * @brief FreeRTOS stack-overflow hook (configCHECK_FOR_STACK_OVERFLOW=2).
 * Silent stack corruption looks like a hang; this names the culprit instead.
 */
void vApplicationStackOverflowHook(TaskHandle_t xTask, char *pcTaskName)
{
    (void)xTask;
    LWIP_PLATFORM_DIAG(("\r\n!!! STACK OVERFLOW in task '%s' !!!\r\n", pcTaskName));
    taskDISABLE_INTERRUPTS();
    for (;;)
        ;
}

#if APP_DUALCORE
#include "mcmgr.h"
#endif

int main(void)
{
#if APP_DUALCORE
    (void)MCMGR_Init(); /* mailbox + event table; core 1 is started later by app_dualcore_start() */
#endif
    BOARD_InitHardware();

    init_task_init();

    /* run RTOS */
    vTaskStartScheduler();

    /* should not reach this statement */
    for (;;)
        ;
}

/*!
 * @brief Starts initialization task.
 */
static void init_task_init(void)
{
    /* create server thread in RTOS */
    if (sys_thread_new("init_task", init_task, NULL, INIT_THREAD_STACKSIZE, INIT_THREAD_PRIO) == NULL)
    {
        LWIP_ASSERT("init_task creation failed", 0);
    }
}

/*!
 * @brief Initializes crypto hw, lwIP stack and starts application task.
 */
static void init_task(void *arg)
{
    const ip_addr_t *dns_address;
    const char *str_ip;
    psa_status_t status;
    uint8_t numdns;

    LWIP_UNUSED_ARG(arg);

    ethernetif_config_t enet_config = {.phyHandle   = &phyHandle,
                                       .phyAddr     = EXAMPLE_PHY_ADDRESS,
                                       .phyOps      = EXAMPLE_PHY_OPS,
                                       .phyResource = EXAMPLE_PHY_RESOURCE,
                                       .srcClockHz  = EXAMPLE_CLOCK_FREQ,
#ifdef configMAC_ADDR
                                       .macAddress = configMAC_ADDR
#endif
    };

    https_client_task_context_t client_context = {
        .host             = EXAMPLE_HOST,
        .port             = EXAMPLE_PORT,
        .path             = EXAMPLE_PATH,
        .max_request_len  = EXAMPLE_MAX_REQUEST_LENGTH,
        .max_response_len = EXAMPLE_MAX_RESPONSE_LENGTH,
        .iterations       = EXAMPLE_ITERATIONS,
        .tls_mode         = EXAMPLE_TLS_MODE,
    };

    LWIP_PLATFORM_DIAG(("***********************************************************\r\n"));
    LWIP_PLATFORM_DIAG(("FOCAL hackathon - FRDM-MCXN947 handshake benchmark [step 4: hybrid KEX + ML-DSA-65/ECDSA auth, mode %d]\r\n",
                        EXAMPLE_TLS_MODE));
    LWIP_PLATFORM_DIAG(("Target: " EXAMPLE_HOST " port %d path " EXAMPLE_PATH "\r\n", EXAMPLE_PORT));
    LWIP_PLATFORM_DIAG(("***********************************************************\r\n"));

    status = psa_crypto_init();
    LWIP_ASSERT("psa_crypto_init() has failed\r\n", status == PSA_SUCCESS);

    tcpip_init(NULL, NULL);

    /* Set MAC address. */
#ifndef configMAC_ADDR
    (void)SILICONID_ConvertToMacAddr(&enet_config.macAddress);
#endif

#if LWIP_IPV4
    netifapi_netif_add(&netif, NULL, NULL, NULL, &enet_config, EXAMPLE_NETIF_INIT_FN, tcpip_input);
#else
    netifapi_netif_add(&netif, &enet_config, EXAMPLE_NETIF_INIT_FN, tcpip_input);
#endif /* LWIP_IPV4 */
    netifapi_netif_set_default(&netif);
    netifapi_netif_set_up(&netif);
#if LWIP_IPV4
    netifapi_dhcp_start(&netif);
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
    LOCK_TCPIP_CORE();
    netif_create_ip6_linklocal_address(&netif, 1);
    UNLOCK_TCPIP_CORE();
#endif /* LWIP_IPV6 */

    while (ethernetif_wait_linkup(&netif, 5000) != ERR_OK)
    {
        LWIP_PLATFORM_DIAG(
            ("PHY Auto-negotiation failed. Please check the cable connection and link partner setting.\r\n"));
    }

#if LWIP_IPV4
#if EXAMPLE_HOST_IS_IPV6
    /* Target is IPv6: DHCPv4 is best-effort only, don't hold up the boot. */
    LWIP_PLATFORM_DIAG(("Trying IPv4 DHCP (3s timeout)...\r\n"));
    (void)ethernetif_wait_ipv4_valid(&netif, 3000);
#else
    LWIP_PLATFORM_DIAG(("Waiting for IPv4 DHCP lease (%d s timeout)...\r\n", EXAMPLE_DHCP_TIMEOUT_MS / 1000));
    if (ethernetif_wait_ipv4_valid(&netif, EXAMPLE_DHCP_TIMEOUT_MS) != ERR_OK)
    {
        LWIP_PLATFORM_DIAG(("No DHCPv4 lease after %d s - trying anyway.\r\n", EXAMPLE_DHCP_TIMEOUT_MS / 1000));
    }
#endif /* EXAMPLE_HOST_IS_IPV6 */
#endif /* LWIP_IPV4 */

    LOCK_TCPIP_CORE();
#if LWIP_IPV4
    LWIP_PLATFORM_DIAG((" IPv4 Address     : %s\r\n", ipaddr_ntoa(&netif.ip_addr)));
    LWIP_PLATFORM_DIAG((" IPv4 Subnet mask : %s\r\n", ipaddr_ntoa(&netif.netmask)));
    LWIP_PLATFORM_DIAG((" IPv4 Gateway     : %s\r\n", ipaddr_ntoa(&netif.gw)));
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
    set_ipv6_valid_state_cb(netif_ipv6_callback);
    print_ipv6_addresses(&netif);
#endif /* LWIP_IPV6 */

    for (numdns = 0U; numdns < DNS_MAX_SERVERS; numdns++)
    {
        dns_address = dns_getserver(numdns);
        str_ip      = "-";
        if (!ip_addr_isany(dns_address))
        {
            str_ip = ipaddr_ntoa(dns_address);
        }
        LWIP_PLATFORM_DIAG((" DNS Server%u      : %s\r\n", numdns, str_ip));
    }

    LWIP_PLATFORM_DIAG(("***********************************************************\r\n\r\n"));
    UNLOCK_TCPIP_CORE();

#if LWIP_IPV6 && EXAMPLE_HOST_IS_IPV6
    LWIP_PLATFORM_DIAG(("Waiting for IPv6 SLAAC global address...\r\n"));
    const TickType_t slaac_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(15000);
    bool have_global = false;
    while (xTaskGetTickCount() < slaac_deadline && !have_global)
    {
        LOCK_TCPIP_CORE();
        for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
        {
            if (ip6_addr_isvalid(netif_ip6_addr_state(&netif, i)) &&
                !ip6_addr_islinklocal(netif_ip6_addr(&netif, i)))
            {
                have_global = true;
                break;
            }
        }
        UNLOCK_TCPIP_CORE();
        if (!have_global)
        {
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }
    if (!have_global)
    {
        LWIP_PLATFORM_DIAG(("No global IPv6 address after 15s — trying anyway.\r\n"));
    }
    else
    {
        LOCK_TCPIP_CORE();
        print_ipv6_addresses(&netif);
        UNLOCK_TCPIP_CORE();
    }
#endif /* LWIP_IPV6 && EXAMPLE_HOST_IS_IPV6 */

    /* Start application task */
    app_https_client_task_init(&client_context, HTTPS_CLIENT_THREAD_STACKSIZE, HTTPS_CLIENT_THREAD_PRIO);

    vTaskDelete(NULL);
}

#if LWIP_IPV6
static void print_ipv6_addresses(struct netif *netif)
{
    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
        const char *str_ip = "-";
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)))
        {
            str_ip = ip6addr_ntoa(netif_ip6_addr(netif, i));
        }
        LWIP_PLATFORM_DIAG((" IPv6 Address%d    : %s\r\n", i, str_ip));
    }
}

static void netif_ipv6_callback(struct netif *cb_netif)
{
    LWIP_PLATFORM_DIAG(("\r\nIPv6 address update, valid addresses:\r\n"));
    print_ipv6_addresses(cb_netif);
    LWIP_PLATFORM_DIAG(("\r\n"));
}
#endif /* LWIP_IPV6 */

#endif /* LWIP_SOCKET */
