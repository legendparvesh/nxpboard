/*
 * FOCAL hackathon - core 1 worker board init (from the SDK multicore hello_world core 1).
 * Core 0 has already configured clocks and pins; core 1 only needs its own
 * SystemCoreClock for the record.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "fsl_common.h"
#include "fsl_clock.h"
#include "pin_mux.h"
#include "board.h"
#include "app.h"

void BOARD_InitHardware(void)
{
    CLOCK_EnableClock(kCLOCK_Gpio0);
    BOARD_InitBootPins();
    SystemCoreClock = CLOCK_GetCoreSysClkFreq();
}
