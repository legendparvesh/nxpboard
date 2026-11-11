# FOCAL Hackathon — FRDM-MCXN947 Handshake Benchmark

Baseline firmware for the FOCAL semi-hackathon. The board connects to the
challenge server over HTTPS, prints what the server returns, and reports
how long the TLS handshake took. Start from this scaffold and
accelerate the NTT operations in the hybrid PQC key exchange using the
MCX N947's NPU IP.

## FOCAL results and migration guide

* [docs/FOCAL-report.md](docs/FOCAL-report.md) — results, comparison vs baseline, acceleration analysis, migration guide.
* [docs/benchmarks.md](docs/benchmarks.md) — raw log of every benchmark run.
* `app/` is the untouched baseline; `app_tls13/` is the migrated firmware (TLS 1.3, X25519MLKEM768, ML-DSA-44 + ECDSA device auth).
  Build it with `make patch-sdk && make flash APP_NAME=app_tls13`.

## Hardware

* development board
* One USB-C cable (programmer + UART) between host and board
* One Ethernet cable between host and board's RJ45

## Board hardware mods required for Ethernet

The Ethernet PHY on FRDM-MCXN947 needs
the 50 MHz reference clock jumpered externally:

* **JP13**: jumper on pins 2–3
* **R274**: populated

Without these, the LAN8741 PHY will not link. Your board should already be modded.

## Layout

```
nxpboard/
├── app/                     # authoritative application sources (edit here)
│   ├── freertos/            #   mounted at sdk/mcuxsdk/examples/focal_challenge/
│   │   ├── main.c                  # init, print banner, start client task
│   │   ├── app_mbedtls_socket.c    # TLS setup + handshake timing
│   │   ├── app_corehttp.c          # coreHTTP transport glue
│   │   ├── app_https_client_task.c # the HTTPS request loop
│   │   ├── app_ca_bundle.c         # empty — server is self-signed
│   │   ├── prj.conf                # Kconfig fragment for this app
│   │   └── CMakeLists.txt
│   └── board_port/
│       └── freertos/        #   mounted at sdk/mcuxsdk/examples/_boards/frdmmcxn947/focal_challenge/
│           ├── pin_mux.{c,h}       # ENET pin muxing + console
│           └── cm33_core0/
│               ├── hardware_init.c # clocks, PHY MDIO
│               ├── app.h           # board-level #defines
│               └── prj.conf        # core-local Kconfig
├── sdk/                     # NXP MCUXpresso SDK (west workspace) — not under version control
├── toolchain/               # downloaded ARM GNU Toolchain 14.2.rel1
├── .venv/                   # Python venv with west + pyocd + pyserial
├── Makefile                 # all commands below
└── README.md                # this file
```

The build graft is done by two symlinks inside the SDK tree:

* `sdk/mcuxsdk/examples/focal_challenge/` -> `app/`
* `sdk/mcuxsdk/examples/_boards/frdmmcxn947/focal_challenge/` -> `app/board_port/`

`make graft` recreates them if ever lost (for example if this folder was transferred over a FAT formatted thumb drive).

## One-time setup (fresh checkout)

```sh
make setup
```

This creates a Python venv, downloads the ARM GNU toolchain, fetches the
NXP SDK subset needed for FRDM-MCXN947 (lwIP, mbedTLS, FreeRTOS, coreHTTP,
ELS/PKC), and wires in the application sources. Expect ~2.5 GB of SDK
download and 3–5 minutes on a fast link. Nothing in `/usr` is touched —
the whole environment lives under `nxpboard/`.

Prereqs that must be present system-wide:

* `python3` ≥ 3.8 (for the venv)
* `cmake` ≥ 3.22
* `ninja`
* `git`
* `wget`

## workflow

```sh
make           # compile, flash, then open the UART monitor
make build     # just compile
make flash     # compile + flash (sector-erase the used flash region)
make monitor   # open /dev/ttyACM0 @ 115200 8N1 (picocom → screen → minicom → miniterm I had a hard time guessing what people would use.)
make reset     # soft-reset the board via CMSIS-DAP
make clean     # delete the build tree
```

Tweak these if your laptop differs:

* `SERIAL_PORT` (default `/dev/ttyACM0`) — the MCU-Link VCOM
* `PYOCD_TARGET` (default `mcxn947vdf`) — pyocd DFP target name
* `BAUD` (default `115200`)

The NXP SDK's CMake generator duplicates sources on reconfigure, which
overflows flash on the second build. The Makefile works around this with
`west build -p always`. Each build is ~3.5 s on my machine; so this should not be too expensive for you.

## Network

The challenge server lives at https://focal-hackathon.iti.uni-luebeck.de
and is reachable over **IPv4 at `193.30.40.242:443`** (address provided by
the organisers) and over IPv6 at `[2a0f:7cc7:7cc7:7c40::94ad]:443`.

The firmware defaults to the IPv4 address (`EXAMPLE_HOST` in
`app/freertos/main.c`): plug the board's RJ45 into any switch or router that
hands out DHCPv4 leases and it will connect directly. The firmware waits up to
15 s for a lease before trying anyway.

To go back to IPv6, set `EXAMPLE_HOST` to the IPv6 literal and
`EXAMPLE_HOST_IS_IPV6` to `1`; the board then picks up a global prefix via
SLAAC (use `ipv6-share.sh` if your uplink has IPv6 but the switch does not
advertise it).

## What the firmware does

On reset:

1. Brings up the LAN8741 PHY and waits for link.
2. Waits for a DHCPv4 lease (15 s timeout) — needed for the IPv4 server.
3. Also autoconfigures IPv6 via SLAAC from RA (only waited for when
   `EXAMPLE_HOST_IS_IPV6=1`).
4. Opens a TCP connection to the test server.
5. Runs mbedTLS with `MBEDTLS_SSL_VERIFY_NONE` (self-signed server) and
   times the handshake with `xTaskGetTickCount`.
6. Sends `GET /frdm-mcxn947 HTTP/1.1` via coreHTTP and prints the
   response body — the challenge server echoes back
   `{"handshake_method":…,"client":…,"request_uri":…}`.

Example UART output (legacy ECDHE handshake):

```
***********************************************************
FOCAL hackathon - FRDM-MCXN947 handshake benchmark
Target: 2a0f:7cc7:7cc7:7c40::94ad port 443 path /frdm-mcxn947
***********************************************************
Initializing PHY...
Trying IPv4 DHCP (3s timeout)...
 IPv4 Address     : 0.0.0.0
 IPv6 Address0    : FE80::5627:8DFF:FEE6:C20E
 IPv6 Address1    : 2a0f:7cc7:…:5627:8dff:fee6:c20e
Connecting to [2a0f:7cc7:7cc7:7c40::94ad]:443...
Performing SSL/TLS handshake...
SSL: Protocol: TLSv1.2, cipher suite: TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
=== TLS handshake took 196 ms (196 RTOS ticks) ===
Response code: 200
Response body:
{"handshake_method":"legacy","client":"2a0f:7cc7:…","request_uri":"/frdm-mcxn947"}
```

