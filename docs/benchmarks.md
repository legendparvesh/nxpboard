# FOCAL hackathon — benchmark log (FRDM-MCXN947)

All numbers measured on the board with the harness in `app*/freertos/app_https_client_task.c`:
15 rounds of TCP connect + TLS handshake + `GET /frdm-mcxn947`, 200 ms pause between rounds,
timings from the 1 ms FreeRTOS tick. **Compare medians** — single network stalls distort min/avg/max.

Test setup (2026-11-11): board on Ethernet behind the laptop's shared IPv4 connection
(10.42.0.0/24, hotel Wi-Fi uplink), server `193.30.40.242:443`, certificate not verified
(`MBEDTLS_SSL_VERIFY_NONE`, self-signed RSA-3072 `CN=focalhackathon`). Network RTT ≈ 20 ms
(from the TCP connect time).

Phases per round:

| Phase | What it covers |
|---|---|
| TLS setup | `app_mbedtls_socket_connect()` minus TCP connect minus handshake: entropy + CTR-DRBG seed, `mbedtls_ssl_config_defaults`, `mbedtls_ssl_setup` (I/O buffer allocation), hostname |
| TCP connect | `connect()` on the lwIP socket |
| TLS handshake | `mbedtls_ssl_handshake()` until it returns 0 |
| HTTP GET | `HTTPClient_Send()` request + full response (in TLS 1.3 this also absorbs the server's Finished check and NewSessionTicket messages, see note) |
| Full round | start of setup to end of GET |

## Run 1 — baseline: `app/`, TLS 1.2, ECDHE-RSA

Build: mbedTLS 3.6.7 NXP port, `MBEDTLS_SSL_PROTO_TLS1_2` only. Flash 426 KB, RAM (bss) 167 KB.
Cipher suite `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`. Server reports `"handshake_method":"legacy"`.

| Phase | min | median | avg | max |
|---|---|---|---|---|
| TLS setup | — | ~75 (inferred: round − tcp − handshake − http) | | |
| TCP connect | 19 | 23 | 43 | 225 |
| TLS handshake | 132 | **140** | 189 | 531 |
| HTTP GET | 19 | 26 | 44 | 257 |
| Full round | 249 | **266** | 356 | 895 |

Bytes: handshake tx 321 B / rx 1841 B; full round tx 464 B / rx 2064 B.

## Run 2 — step 2: `app_tls13/`, TLS 1.3, X25519/P-256 + RSA

Build: as above plus `MBEDTLS_SSL_PROTO_TLS1_3` + `MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE`
(via `app_mbedtls_user_config.h`), client pinned to TLS 1.3. Flash 448 KB (+21 KB), RAM (bss) 167 KB.
Cipher suite `TLS1-3-AES-128-GCM-SHA256`, classical key share only. Server reports `legacy`
(it only says `hybrid-pqc` when the X25519MLKEM768 group is negotiated).

| Phase | min | median | avg | max |
|---|---|---|---|---|
| TLS setup | 74 | **74** | 79 | 157 |
| TCP connect | 19 | 22 | 25 | 50 |
| TLS handshake | 49 | **55** | 59 | 88 |
| HTTP GET | 76 | 84 | 266 | 2578 |
| Full round | 223 | **237** | 430 | 2866 |

Bytes: handshake tx 295 B / rx 1797 B; full round tx 444 B / rx 2157 B.

## Run 3 — `app_tls13/`, TLS 1.3, **100 rounds**

Same build and setup as run 2, `EXAMPLE_ITERATIONS=100`. 100/100 rounds OK.

| Phase | min | median | avg | max |
|---|---|---|---|---|
| TLS setup | 74 | **74** | 74 | 163 |
| TCP connect | 17 | 22 | 35 | 270 |
| TLS handshake | 49 | **58** | 79 | 400 |
| HTTP GET | 28 | 84 | 118 | 2052 |
| Full round | 221 | **250** | 308 | 2367 |

Bytes: handshake tx 295 B / rx 1797 B; full round tx 444 B / rx 2157 B.
Stalls (round > 500 ms): 7 of 100, clustered (rounds 22–24, 48–50, 77–81, 99) — uplink, not board.
Setup was exactly 74–75 ms in 99/100 rounds (163 ms in round 1 only): a fixed per-connection cost.

## Run 4 — `app/`, TLS 1.2, 100 rounds — **network-degraded, not comparable**

Same build as run 1, 100 rounds, 100/100 OK. Run immediately after run 3, but the uplink had
degraded: TCP connect median **49 ms** (vs 22 ms in run 3), 15 rounds with TCP connect > 300 ms.
Board-side minima match run 1 (handshake 130 ms, round 262 ms), medians are inflated by stalls
(handshake 231, round 510). Kept for the record, not used for comparison.

Setup split from this run (round 1, verbose): `entropy + CTR-DRBG seed took 74 ms`,
`mbedtls_ssl_setup took 0 ms` → the fixed 74 ms per connection is entirely TRNG entropy
gathering for the per-connection DRBG seed.

**Method change:** sequential runs are at the mercy of Wi-Fi drift. From here on the comparison
firmware alternates TLS 1.2 and TLS 1.3 every round (A/B interleaved, `EXAMPLE_TLS_MODE=0` in
`app_tls13/`), so both protocols see the same network at the same moments. TCP connect
(no crypto) serves as the network-quality control column.

## Run 5 — A/B interleaved, TLS 1.2 vs TLS 1.3, 100 rounds (50 + 50)

`app_tls13/`, `EXAMPLE_TLS_MODE=0`, `APP_DRBG_SEED_ONCE=0`. Odd rounds TLS 1.3, even rounds TLS 1.2.
100/100 OK. Network was poor throughout (TCP connect median ≈ 60 ms, vs 22 ms in runs 2–3),
**but equally poor for both arms** — that is what the interleaving buys.

| Phase (median, ms) | TLS 1.2 | TLS 1.3 | Δ |
|---|---|---|---|
| TCP connect (control) | 58 | 60 | same network |
| TLS setup | 74 | 74 | same |
| TLS handshake | 268 | 78 | −190 |
| HTTP GET | 62 | 179 | +117 |
| **Full round** | **575** | **501** | **−74 (−13 %)** |
| Full round, min | 278 | 236 | −42 |

Bytes unchanged: TLS 1.2 handshake 321/1841 B, TLS 1.3 295/1797 B.

## Run 6 — A/B interleaved, TLS 1.2 vs TLS 1.3, **DRBG seeded once**, 100 rounds (50 + 50)

As run 5 but `APP_DRBG_SEED_ONCE=1`: the CTR-DRBG is seeded from the TRNG once (first connection)
and reused; mbedTLS reseeds automatically after its reseed interval. Clean network
(TCP connect median 21–22 ms in both arms). 100/100 OK.

| Phase (median, ms) | TLS 1.2 | TLS 1.3 | Δ |
|---|---|---|---|
| TCP connect (control) | 21 | 22 | same network |
| TLS setup | **0** | **0** | was 74 |
| TLS handshake | 143 | 55 | −88 |
| HTTP GET | 22 | 86 | +64 |
| **Full round** | **201** | **170** | −31 |
| Full round, min | 165 | 146 | |

Security note: reusing a seeded DRBG across connections is the normal mode of operation for a
NIST SP 800-90A DRBG; each connection still draws fresh ClientHello randomness and a fresh
ephemeral key, so forward secrecy is unaffected. Assumption: the MCXN947 TRNG is a sound
entropy source. A multi-task application would guard the shared DRBG with a mutex.

## Run 7 — step 3: three arms interleaved, **hybrid X25519MLKEM768** / TLS 1.3 / TLS 1.2, 100 rounds

`app_tls13/`, `EXAMPLE_TLS_MODE=6`, `APP_DRBG_SEED_ONCE=1`, SDK mbedTLS patched with
`patches/mbedtls3x-x25519mlkem768.patch`, ML-KEM-768 from mlkem-native (portable C, no
acceleration). Rounds cycle hybrid → TLS 1.3 → TLS 1.2 (34/33/33). 100/100 OK.
Clean network (TCP connect median 25–26 ms in all arms).

| Phase (median, ms) | TLS 1.2 | TLS 1.3 classic | TLS 1.3 + X25519MLKEM768 |
|---|---|---|---|
| TCP connect (control) | 26 | 25 | 26 |
| TLS setup | 0 | 0 | 0 |
| TLS handshake | 156 | 61 | **102** |
| HTTP GET | 25 | 93 | 92 |
| **Full round** | 213 | 181 | **231** |
| Full round, min | 180 | 153 | 195 |
| Handshake bytes tx / rx | 309 / 1841 | 279 / 1797 | **1465 / 2885** |
| Round bytes tx / rx | 452 / 2064 | 428 / 2157 | 1614 / 3249 |

Correctness: every hybrid round completed the handshake *and* the HTTP GET returned 200, which
requires both sides to have derived the same `ML-KEM ss || X25519 ss`. Bytes match the spec:
+1184 B (ML-KEM-768 encapsulation key) sent, +1088 B (ciphertext) received.

Cost of the PQ half vs TLS 1.3 classic: **+41 ms handshake, +50 ms full round, +2.3 KB on the
wire**; flash 448 → 460 KB (+11 KB incl. Keccak); RAM: client task stack 16 → 32 KB (ML-KEM
keygen/decaps keep ~8–10 KB of polynomial vectors on the stack), +3.5 KB handshake state.

Lesson learned: with the original 16 KB task stack the hybrid handshake *hung silently*
(configCHECK_FOR_STACK_OVERFLOW was off). Enabled overflow checking + hook; now 32 KB.

## Run 8 — on-board crypto micro-benchmark (DWT cycle counter, 150 MHz, min of 10)

`app_tls13/freertos/app_pqc_bench.c`, run once at start-up. Cycle-exact; minimum over 10 runs
(interrupts can only add cycles). Converted at 150 MHz.

| Operation | cycles | ms | note |
|---|---|---|---|
| ML-KEM-768 keypair (client, ClientHello) | 994 497 | **6.63** | mlkem-native, portable C |
| ML-KEM-768 encaps (server side, reference) | 1 122 167 | 7.48 | |
| ML-KEM-768 decaps (client, key schedule) | 1 379 016 | **9.19** | |
| Keccak-f1600 ×4 (4 permutations) | 56 510 | 0.377 | → 14 100 cyc / permutation |
| SHA3-512, 64 B (= G) | 15 666 | 0.104 | |
| SHAKE256 33 B → 128 B (= PRF) | 15 821 | 0.105 | |
| gen_matrix A (9 polys, SHAKE128 rejection sampling) | 461 900 | **3.08** | runs in keypair *and* decaps |
| polyvec NTT (3 polys) | 59 487 | 0.397 | 19 800 cyc / poly |
| polyvec invNTT + tomont (3 polys) | 101 331 | 0.676 | |
| polyvec mulcache (3 polys) | 6 212 | 0.041 | |
| X25519 keygen + export (PSA) | 1 623 520 | **10.82** | **software** — PKC not used by the port |
| X25519 shared secret (PSA) | 813 253 | **5.42** | software |
| ECDSA P-256 sign (PSA) | 1 706 326 | 11.38 | software |
| ECDSA P-256 verify (PSA) | 3 028 607 | **20.19** | software — the classical half of hybrid auth |
| SHA-256, 1 KB (PSA) | 6 276 | 0.042 | **hardware** (ELS) |
| SHA3-256, 1 KB (software SHAKE) | 124 096 | 0.827 | 20× slower than HW SHA-256 |

### Analysis

* **ML-KEM crypto on the client = 6.6 + 9.2 = 15.8 ms per handshake**, i.e. only ~40 % of the
  +41 ms the hybrid arm costs over TLS 1.3 classic (run 7). The remaining ~25 ms is transport:
  +2.3 KB on the wire, the server's encapsulation, and lwIP's receive window (`TCP_WND` = 2 × MSS
  = 2920 B) which is smaller than the server's ~2.9 KB first flight → likely one extra ACK round trip.
* **Inside ML-KEM, hashing dominates**: gen_matrix alone is 3.1 ms and runs twice per handshake
  (keypair + re-encryption in decaps); with the PRF/G/J calls, Keccak is ≈ 7.8 ms ≈ 50 % of the
  ML-KEM time. **NTT/invNTT is ≈ 2 ms ≈ 13 %.**
* **NPU / PowerQuad verdict (preliminary):** even a free, zero-latency NTT would save ≤ 2 ms of a
  231 ms round (< 1 %), before counting data-transfer and setup costs. Not a worthwhile target.
  The lever is Keccak, for which there is no hardware on the MCXN947; optimised Cortex-M
  assembly (2–3× faster than portable C) would recover ~4–5 ms.
* **Biggest finding: the classical crypto runs in software.** X25519 (16.2 ms per handshake) is
  slower than all of ML-KEM; ECDSA P-256 verify is 20 ms. The ELS/PKC accelerator exists but the
  SDK's mbedTLS 3.x port only hooks hardware entropy and hashing (SHA-256 is 20× faster than
  software SHA-3, so the hash path *is* hardware). Wiring the PKC into the PSA ECC path would cut
  ~15 ms from every arm now and ~18 ms from the ECDSA half of hybrid authentication later.
  This is a "software support" obstacle in the sense of the challenge brief.

Ranked acceleration plan: (1) lwIP window/pbuf tuning, (2) ELS/PKC for X25519 + ECDSA,
(3) optimised Keccak assembly, (4) NPU/PowerQuad NTT — documented negative result.

## Run 9 — lwIP receive window tuned, three arms, 100 rounds

As run 7, plus in `app_tls13/freertos/prj.conf`: `TCP_WND` 2×MSS → **4×MSS** (2920 → 5840 B),
`PBUF_POOL_SIZE` 5 → 8, `MEM_SIZE` 22 → 32 KB (+17 KB RAM). Motivation: the server's first
flight in the hybrid handshake (~2.9 KB) exceeded the old window, forcing an extra ACK round trip.
100/100 OK, clean network (TCP connect median 20–21 ms all arms). Round 1 JSON:
`"handshake_method":"hybrid-pqc"`.

| Phase (median, ms) | TLS 1.2 | TLS 1.3 classic | TLS 1.3 + X25519MLKEM768 |
|---|---|---|---|
| TCP connect (control) | 21 | 21 | 20 |
| TLS handshake | 132 (was 156) | 55 (was 61) | **73 (was 102)** |
| HTTP GET | 21 | 81 | 81 |
| **Full round** | 174 (was 213) | 159 (was 181) | **175 (was 231)** |
| Full round, min | 160 | 146 | 165 |

The hybrid arm is now **+16 ms over TLS 1.3 classic — equal to the measured ML-KEM crypto
cost (6.6 + 9.2 = 15.8 ms, run 8)**. The transport overhead of the extra 2.3 KB is gone.
Lesson: the first PQC cost that hurt was not crypto but a TCP buffer sized for ~2 KB handshakes.

## Run 10 — step 4: hybrid authentication ML-DSA-65 + ECDSA P-256, four arms, 100 rounds

`app_tls13/`, `EXAMPLE_TLS_MODE=7`: arms `MLKEM+MLDSAauth` / `TLS1.3+MLKEM` / `TLS1.3` / `TLS1.2`,
25 rounds each, interleaved. ML-DSA-65 from mldsa-native (portable C, `REDUCE_RAM`, large
buffers on the FreeRTOS heap), ECDSA P-256 via PSA (software). Device keys generated at boot
(ML-DSA-65 keypair 25.4 ms, ECDSA 11.2 ms). In the auth arm the board signs the TLS 1.3 exporter
value (32 B, label `EXPORTER-focal-hybrid-auth`) with both algorithms, verifies both itself, and
sends `X-Hybrid-Auth: mldsa65=<b64>;ecdsa-p256=<b64>` (4520 chars) with the GET.
100/100 OK, 0 self-verify failures, server answered 200 / `hybrid-pqc` to every signed request.
Network slightly worse than run 9 (TCP connect median 24–27 ms vs 20).

| Phase (median, ms) | TLS 1.2 | TLS 1.3 | TLS 1.3 + ML-KEM | TLS 1.3 + ML-KEM + hybrid auth |
|---|---|---|---|---|
| TCP connect (control) | 27 | 26 | 24 | 26 |
| TLS handshake | 153 | 61 | 77 | 77 |
| Hybrid auth (sign + self-verify) | – | – | – | **155** (min 97, max 463) |
| HTTP GET | 26 | 90 | 92 | 52 |
| **Full round** | 206 | 186 | 201 | **379** |
| Request bytes tx | 452 | 428 | 1614 | **6142** |

Authentication micro-benchmark (DWT, 10 runs):

| Operation | min | median | max | note |
|---|---|---|---|---|
| ML-DSA-65 keypair | 25.42 | 25.42 | 25.45 | |
| **ML-DSA-65 sign (32 B)** | **36.5** | **115.3** | **363.6** | rejection sampling: ~36 ms/attempt; sig 3309 B |
| ML-DSA-65 verify | 25.46 | 25.46 | 25.55 | |
| ECDSA P-256 sign (PSA, software) | | 11.4 | | |
| ECDSA P-256 verify (PSA, software) | | 20.3 | | |
| RSA-2048 sign (mbedTLS test key, software) | 197.7 | 197.7 | 197.7 | RSA-3072 sign ≈ 3–4× this |
| RSA-2048 verify | 2.20 | 2.20 | 2.21 | |
| **RSA-3072 verify, live server key** | | **4.42** | | what the baseline client does per handshake |

Per-round averages in the auth arm: ML-DSA-65 sign 122 ms, verify 25.5 ms, ECDSA sign 11.4 ms,
verify 20.3 ms. (HTTP GET is *lower* in this arm because the server's NewSessionTicket records
arrive during the ~155 ms of signing and are already buffered when the GET reads.)

### Findings

* **Target missed for hybrid KEX + hybrid auth as demonstrated: 379 ms vs 266 ms (+113 ms).**
* The direction of the comparison matters:
  * **Verifier side** (board checks a hybrid signature instead of RSA-3072): ML-DSA-65 verify
    25.5 + ECDSA verify 20.3 = 46 ms vs 4.4 ms → +41 ms on the 175 ms hybrid-KEX round
    = ~216 ms, **50 ms under baseline**. Replacing the server's RSA signature meets the target.
  * **Signer side** (board authenticates itself): ML-DSA-65 + ECDSA sign ≈ 126 ms vs RSA-2048
    sign 198 ms (RSA-3072 ≈ 600–700 ms). **Hybrid PQ signing is 2–5× faster than RSA signing
    on this chip.**
* Of the 155 ms, 46 ms is self-verification (demo artifact: no verifier available); a real
  deployment is ~333 ms. The remaining gap is ML-DSA-65 signing: ~115 ms median with large
  variance (1–10 rejection-sampling attempts at ~36 ms each). ECDSA adds ~31 ms in software.
* Actionable levers, in order: ML-DSA-44 (≈2× faster sign, 2420 B sig); ELS/PKC hardware ECDSA
  (≈ −30 ms); optimised Keccak (ML-DSA is also Keccak-dominated: matrix expansion + per-attempt
  sampling). Estimate for ML-DSA-44 + software ECDSA, no self-verify: 175 + ~55 + 11 ≈ 240 ms.
* Communication overhead of hybrid auth: +4.5 KB per authenticated request (ML-DSA-65 signature
  3309 B base64-encoded + ECDSA 64 B); public keys 1952 + 64 B.
* Memory: ML-DSA-65 signing needs ~68 KB working memory (heap-backed; task stack would not do);
  flash 463 → 489 KB (+26 KB); heap raised to 192 KB.

## Run 11 — step 4 with **ML-DSA-44** instead of ML-DSA-65, four arms, 100 rounds

Same as run 10 with `MLD_CONFIG_PARAMETER_SET 44` (NIST category 2; pk 1312 B, sk 2560 B,
signature 2420 B). Clean network (TCP connect median 20–23 ms, all arms). 100/100 OK,
0 self-verify failures, server 200 / `hybrid-pqc` for every signed request (header 3336 chars).

| Phase (median, ms) | TLS 1.2 | TLS 1.3 | TLS 1.3 + ML-KEM | TLS 1.3 + ML-KEM + hybrid auth (ML-DSA-44) |
|---|---|---|---|---|
| TCP connect (control) | 20 | 21 | 21 | 23 |
| TLS handshake | 134 | 56 | 73 | 73 |
| Hybrid auth (sign + self-verify) | – | – | – | **112** (min 73, max 304) |
| HTTP GET | 21 | 82 | 84 | 47 |
| **Full round** | 181 | 162 | 179 | **289** |
| Request bytes tx | 452 | 428 | 1614 | **4958** |

Per-round averages in the auth arm: ML-DSA-44 sign 80 ms, verify 15.2 ms, ECDSA sign 11.4 ms,
verify 20.3 ms.

Authentication micro-benchmark, ML-DSA-44 vs ML-DSA-65 (DWT, 10 runs, ms):

| Operation | ML-DSA-44 min / med / max | ML-DSA-65 min / med / max |
|---|---|---|
| keypair | 14.3 / 14.7 / 14.8 | 25.4 / 25.4 / 25.4 |
| **sign (32 B)** | **23.7 / 44.3 / 99.1** | 36.5 / 115.3 / 363.6 |
| verify | 15.3 / 15.3 / 15.3 | 25.5 / 25.5 / 25.6 |
| signature size | 2420 B | 3309 B |

### Findings

* **ML-DSA-44: 289 ms vs 266 ms baseline → +23 ms, target narrowly missed *with self-verify*.**
  The self-verify (15.2 + 20.3 = 35.5 ms) is a demo artifact (no verifier available); the
  deployment case (sign only) is ≈ 253 ms, **under the baseline** — to be measured directly
  (run 12). With ELS/PKC hardware ECDSA signing (11 → ~2 ms) ≈ 244 ms.
* Per-attempt cost of ML-DSA-44 signing ≈ 24 ms; median 2 attempts, worst seen 4.
* Parameter-set choice is the decisive lever for authentication on this class of device:
  ML-DSA-65 in portable C is ~2.5× the cost of ML-DSA-44 and misses the target by ~110 ms.

## Run 12 — five arms incl. **deployment-mode auth (sign only)**, ML-DSA-44, 100 rounds — network degraded

`EXAMPLE_TLS_MODE=9`: `MLKEM+MLDSAsign` (sign, no self-verify) / `MLKEM+MLDSAauth` (sign +
self-verify) / `TLS1.3+MLKEM` / `TLS1.3` / `TLS1.2`, 20 rounds each. 100/100 OK.
**Network poor throughout: TCP connect medians 32–43 ms (vs 20–23 in runs 9/11)**, so absolute
values are not comparable to the 266 ms baseline; within-run comparison remains valid.

| Phase (median, ms) | TLS 1.2 | TLS 1.3 | +ML-KEM | +ML-KEM +auth (sign+verify) | +ML-KEM +auth (**sign only**) |
|---|---|---|---|---|---|
| TCP connect (control) | 33 | 43 | 38 | 32 | 42 |
| TLS handshake | 188 | 80 | 104 | 84 | 87 |
| Hybrid auth | – | – | – | 118 | **77** |
| HTTP GET | 41 | 133 | 118 | 78 | 79 |
| **Full round** | 290 | 343 | 275 | 356 | **292** |

Within this run: **deployment-mode hybrid authentication (ML-DSA-44 + ECDSA, sign only) costs
the same as the TLS 1.2 arm (292 vs 290 ms) and +17 ms over hybrid KEX alone.** To be
repeated on a clean network for an absolute number against 266 ms.

ML-DSA signing latency is a distribution: per-attempt cost is fixed (ML-DSA-44: 23.7 ms) but the
rejection-sampling attempt count is geometric (FIPS 204 expected ≈ 4.25 attempts for ML-DSA-44,
≈ 5.1 for ML-DSA-65). Measured: micro-benchmark medians 44 ms (run 11) vs 118 ms (run 12) with
identical code/keys; 20-round average 100 ms (= 4.2 attempts, matching the spec); min 23.7,
max observed 200 ms (run 12) / 364 ms (ML-DSA-65, run 10). Deadline-driven designs must budget
for the tail (p99 ≈ 10 attempts ≈ 250 ms for ML-DSA-44 in portable C), not the median.

## Run 13 — **headline run**: five arms, ML-DSA-44, clean network, 100 rounds

Same build as run 12 (`EXAMPLE_TLS_MODE=9`), 20 rounds per arm, interleaved. **TCP connect
median 20 ms in all five arms** → directly comparable to the 266 ms baseline. 100/100 OK,
40/40 signed requests accepted by the server (200 / `hybrid-pqc`), 0 self-verify failures.

| Phase (median, ms) | TLS 1.2 | TLS 1.3 | +ML-KEM | +ML-KEM +auth (sign + self-verify) | **+ML-KEM +auth (sign only)** |
|---|---|---|---|---|---|
| TCP connect (control) | 20 | 20 | 20 | 20 | 20 |
| TLS handshake | 134 | 55 | 72 | 72 | 71 |
| Hybrid auth | – | – | – | 94 (min 74, max 312) | **77** (min 38, max 202) |
| HTTP GET | 21 | 82 | 81 | 41 | 46 |
| **Full round** | 182 | 163 | 175 | **261** | **238** |
| Full round min / max | 169 / 554 | 150 / 547 | 164 / 344 | 205 / 548 | 169 / 586 |
| Request bytes tx | 452 | 428 | 1614 | 4958 | 4958 |

Per-round averages, both auth arms: ML-DSA-44 sign ≈ 77 ms, ECDSA P-256 sign 11.4 ms
(+ self-verify arm: ML-DSA verify 15.3, ECDSA verify 20.3 ms).

## Run 14 — ML-KEM NTT on the PowerQuad matrix engine, four arms, 100 rounds

`EXAMPLE_TLS_MODE=10`: `MLKEM(PQ-NTT)` (hybrid KEX, forward NTTs on the PowerQuad via the
mlkem-native `MLK_USE_NATIVE_NTT` hook) / `TLS1.3+MLKEM` (CPU NTT) / `TLS1.3` / `TLS1.2`.
Implementation: NTT = two 128×128 matrix-vector products (FIPS 203 even/odd form), operands split
into 6-bit limbs for exactness in the engine's float32 datapath, twiddles stored as 8×8 tiles of
16×16 (engine maximum), 128 `PQ_MatrixMultiplication` calls per NTT, CPU accumulation,
limb recombination and reduction mod q. Twiddle tables generated and checked against Algorithm 9
by `tools/gen_pq_ntt_tables.py`. Network mediocre (TCP connect medians 28–35 ms).

Micro-benchmark (DWT, min of 20):

| | cycles | ms |
|---|---|---|
| one 16×16 × 16×4 block product incl. start/wait (1024 MAC) | 1 649 | **1.61 cycles/MAC** |
| NTT, software (Cortex-M33, portable C) | **19 835** | 0.132 |
| NTT, PowerQuad (128 tiled block products) | **293 546** | 1.957 → **14.8× slower** |
| ML-KEM-768 keypair + decaps, NTT on CPU | 999 719 + 1 384 218 | 15.9 |
| ML-KEM-768 keypair + decaps, NTT on PowerQuad | 2 642 195 + 3 026 885 | 37.8 |

Handshake arms (median, ms): hybrid KEX with PowerQuad NTT **105** vs CPU NTT **86** (handshake),
full round **261 vs 241**. TLS 1.3 classic 64 / 212, TLS 1.2 176 / 245.

Correctness (first build): 1 coefficient mismatch in 150 NTTs (38 400 coefficients) and one
handshake of 25 failed with a record-MAC error — a rare wrong NTT. The arithmetic looked exact by
construction (every 16-term dot product < 2²⁴, well inside float32), so runs 15–17 chased a
timing hazard. The real cause turned out to be arithmetic after all — see run 17.

### Analysis

* The PowerQuad can execute ML-KEM's NTT, but **14.8× slower than the CPU butterfly** in this
  (faulty) 6-bit-limb form, and the hybrid handshake gets ~19 ms *slower*. Three measured reasons:
  1. **Complexity class:** the engine offers dense products only; a 256-point NTT is 131 k MACs
     that way, versus ~2 k multiplications for the O(n log n) butterfly the CPU runs.
  2. **16×16 operand limit:** 128 engine invocations per NTT; the 1.61 cycles/MAC already includes
     their start/wait overhead.
  3. **Float32 datapath:** 12-bit modular operands must be split into 6-bit limbs (4× products)
     and reduced mod q on the CPU afterwards.
* Ceiling from the measured throughput: a four-step NTT (16-point and 8-point stages, ≈ 25 k MACs)
  would need ≥ 40 k cycles on the engine before overheads — still 2× the CPU. There is no
  formulation in which this engine wins the NTT.
* The NPU (eIQ Neutron) was not attempted. Correction to an earlier note: the eIQ middleware
  *is* public (`github.com/nxp-mcuxpresso/mcux-sdk-middleware-eiq`, manifest group `eiq`), it is
  just not cloned in this workspace; it ships the MCXN Neutron driver and firmware libraries and
  a raw driver API (`NeutronDriver.h`). What it does not ship is the compiler: the microcode,
  weights and kernels blobs come from `neutron-converter` in NXP's eIQ Toolkit (free download,
  NXP account). The arithmetic objection stands: an int8×int8 datapath with requantised output
  would need 4 (ML-KEM) to 9 (ML-DSA) limb products per transform and cannot return exact 32-bit
  sums through the supported operator path.

## Run 15 — PowerQuad NTT, barrier after `PQ_WaitDone` + engine self-check, four arms, 100 rounds

Same build as run 14 plus `DSB; ISB` after the busy-wait, a 2 000-block engine check and the
correctness test run twice (interrupts enabled / tile loop in a critical section).

```
engine check: 2000 random 16x16x4 block products vs CPU, 0 mismatching -> PASS
correctness (interrupts enabled): 600 NTTs, 153600 coefficients, 10 mismatches -> FAIL
correctness (interrupts masked ): 600 NTTs, 153600 coefficients,  6 mismatches -> FAIL
NTT, PowerQuad: 294456 cycles vs software 19834 -> SLOWER by 14.84x
```

Handshake medians: PQ-NTT 97 ms vs CPU NTT 75 ms; 1 of 25 PQ-NTT handshakes failed (`MAC failed`).
Masking interrupts changes nothing → not an interrupt hazard. The failing coefficient is
almost always **56** (output row 28 = tile row 1, local row 12), occasionally 86 or 102, and
always an even-indexed coefficient — too regular for a random glitch.

## Run 16 — PowerQuad NTT, sentinel-filled result buffer (completion wait on the data itself)

Result buffer pre-filled with 0x7FFFFFFF before each block, CPU spins after BUSY clears until no
sentinel remains, counting how often that wait was needed.

```
correctness (interrupts enabled): 6 mismatches -> FAIL
correctness (interrupts masked ): 5 mismatches -> FAIL
late result writes observed (BUSY clear before data landed): 0
one block product: 2544 cycles (2.48 cycles/MAC, sentinel fill + scan included)
NTT, PowerQuad: 408220 cycles -> SLOWER by 20.58x
```

→ BUSY never clears early. The output side of the engine is cleared; the hazard is not a
race. Note the 2 000-block engine check is statistically useless at this fault rate: with
≈ 1 wrong block in 10 000 it expects 0.2 faults.

## Run 17 — PowerQuad NTT, per-block verify mode: **root cause found**

Every block product of the NTT compared against a CPU reference, faults logged with the operands
and a re-run; engine check raised to 40 000 blocks. The first four faults say it all:

```
block mismatch: tile 9 W_lo out[12][0] engine 32767 vs cpu 34870
block mismatch: tile 9 W_lo out[12][0] engine 32767 vs cpu 34055
block mismatch: tile 9 W_lo out[12][0] engine 32767 vs cpu 33676
block mismatch: tile 9 W_lo out[12][0] engine 32767 vs cpu 33199
```

**The matrix engine clamps every output at +32767 (int16 maximum) even with `outputFormat =
kPQ_32Bit` and a 32-bit result buffer.** A block output is a 16-term sum of products of two
6-bit limbs, up to 63·63·16 = 63 504; sums above 32 767 are rare for random operands (≈ 1 in
10 000 outputs), which is why only ~7·10⁻⁵ of coefficients went wrong. Tile 9, local row 12 is
global output row 28 = coefficient 56: that twiddle row happens to carry large low limbs, hence
the recurrence. Not documented in the SDK driver; the `PQ_SetConfig` output format is honoured
for the width of the write but not for the saturation point. (The serial port dropped after
these lines; the diagnostic build was then reverted.)

## Run 18 — PowerQuad NTT **fixed**: 5-bit coefficient limbs, four arms, 100 rounds

Coefficients split into three 5-bit limbs (x = 1024·x₂ + 32·x₁ + x₀) while the twiddles keep
their two 6-bit limbs, so every block output ≤ 16·63·31 = 31 248 < 32 768. B is 128×6, still 128
engine calls per NTT, tables unchanged. Commit 2ddcc8c. Network good (TCP connect medians
20–23 ms).

```
engine check: 40000 random 16x16x6 block products vs CPU, 0 blocks / 0 outputs wrong -> PASS
correctness: 200 random polyvecs (600 NTTs, 153600 coefficients), 0 mismatches -> PASS
one 16x16 x 16x6 block product (1536 MAC)  :   2790 cycles  (1.81 cycles/MAC)
NTT, software (Cortex-M33, portable C)     :  19834 cycles = 0.132 ms
NTT, PowerQuad (128 tiled block products)  : 471731 cycles = 3.144 ms  -> SLOWER by 23.78x
ML-KEM-768 keypair + decaps, NTT on CPU      : 1000264 + 1384916 cycles = 15.901 ms
ML-KEM-768 keypair + decaps, NTT on PowerQuad: 3712139 + 4097193 cycles = 52.062 ms
```

| Arm | TCP connect | TLS handshake | HTTP GET | Full round | ok |
|---|---|---|---|---|---|
| MLKEM(PQ-NTT) | 22 | **109** | 83 | **217** | 25/25 |
| TLS1.3+MLKEM (CPU NTT) | 20 | **72** | 82 | **179** | 25/25 |
| TLS1.3 | 23 | 55 | 82 | 163 | 25/25 |
| TLS1.2 | 22 | 133 | 22 | 181 | 25/25 |

(medians, ms; 100/100 rounds ok, no MAC failures)

### Analysis

* **Correct now, and slower than before the fix:** the PowerQuad NTT costs 472 k cycles against
  19.8 k on the CPU (**23.8× slower**); the hybrid handshake is **+37 ms** (109 vs 72 ms) and the
  full round +38 ms (217 vs 179). ML-KEM keypair + decaps goes from 15.9 ms to 52.1 ms. The fix
  itself cost 1.5× (6 instead of 4 B columns per block) on top of run 14's 14.8×.
* The result is not an implementation accident but the engine's shape: dense 16×16 products at
  1.6–1.8 cycles/MAC against an O(n log n) butterfly that needs ~2 k multiplications; limb splitting
  for a 12-bit modular operand on a float32 datapath with a 16-bit output clamp; 128 invocations
  per transform. Even a four-step NTT formulation (≈ 25 k MACs) would stay ≥ 2× slower than the
  CPU on this engine.
* Keep `MLKEM(PQ-NTT)` as the measured negative result; the deployment configuration runs the NTT
  on the Cortex-M33 (`app_pq_ntt_enabled = 0`).

## Run 19 — deployment configuration, ML-KEM NTT on CPU vs PowerQuad, two arms, 100 rounds

`EXAMPLE_TLS_MODE=11`: `MLKEM+MLDSAsign` (TLS 1.3, X25519MLKEM768, ML-DSA-44 + ECDSA P-256
device signature, sign only) vs `MLKEM+MLDSA(PQ)` (identical, ML-KEM NTTs on the PowerQuad).
50 rounds per arm. Network good (TCP connect medians 21–22 ms), a few stalls (rounds 21–22,
50–51, 79–81) visible in max/avg only.

| Arm | TCP connect | TLS handshake | Hybrid auth | HTTP GET | Full round | ok |
|---|---|---|---|---|---|---|
| MLKEM+MLDSAsign (CPU NTT) | 22 | **74** | 74 | 48 | **222** | 50/50 |
| MLKEM+MLDSA(PQ) | 21 | **112** | 85 | 48 | **281** | 50/50 |

(medians, ms). Auth averages: ML-DSA sign 86.8 vs 95.8 ms (randomised retry count, not related
to the NTT path), ECDSA sign 11.4 ms both. Request 4958 B sent per round (3.3 KB signature header).

### Analysis

* Confirms run 18 on the full deployment configuration: the PowerQuad arm's handshake is **+38 ms**
  (112 vs 74); the auth column is the same operation in both arms and differs only by the
  ML-DSA retry lottery (medians 74 vs 85, averages 87 vs 96; min 38 in both).
* Full round: **222 ms with the CPU NTT (−44 ms vs the 266 ms baseline), 281 ms with the
  PowerQuad NTT (+15 ms — would miss the target).** The accelerator path turns a passing
  configuration into a failing one.
* The 222 ms here vs 238 ms in run 13 is network and ML-DSA-retry variance, not a code change.

## Run 20 — step 5: hybrid key share precomputed during the TCP connect, two arms, 100 rounds

`EXAMPLE_TLS_MODE=12`: `MLKEM+MLDSA+pre` (deployment configuration, ML-KEM-768 keypair + X25519
key generated by a low-priority helper task while the client task is blocked in `connect()`,
handed to mbedTLS through a hook in the hybrid key-share writer — `app_keyshare.c`,
`MBEDTLS_SSL_TLS1_3_HYBRID_MLKEM_PRECOMPUTED` in the SDK patch) vs `MLKEM+MLDSAsign` (same, key
share generated inline as before). Network good at the end, a few stalls in the first half.

| Arm | TCP connect | TLS handshake | Hybrid auth | HTTP GET | Full round | ok |
|---|---|---|---|---|---|---|
| MLKEM+MLDSA+pre | 21 | **56** | 87 | 58 | **243** | 50/50 |
| MLKEM+MLDSAsign (inline) | 22 | **73** | 94 | 55 | **262** | 50/50 |

```
Precomputed key shares: 50 generated during TCP connect, 50 used, 0 not ready in time (inline fallback); helper stack peak 14040 B
```

First attempt of this build froze at the first `Connecting to` line: the helper task had a 12 KB
stack and its measured peak is 14 040 B. Nothing was printed because stack-overflow checking had
in fact been off all along — `CONFIG_configCHECK_FOR_STACK_OVERFLOW=2` in `prj.conf` was
silently ignored (the Kconfig symbol is a bool; the generated header had the macro commented
out). Set to `=y` (method 1); the helper stack is now 20 KB.

### Analysis

* **Handshake −17 ms (73 → 56), exactly the ML-KEM keypair (6.7 ms) + X25519 keygen (10.8 ms)
  moved off the critical path.** A ~20 ms TCP connect was long enough in 50 of 50 rounds; the
  fallback never triggered.
* The hybrid TLS 1.3 handshake now costs the same as a classical TLS 1.3 handshake (56 vs 55 ms
  in runs 18/19): the client-side cost of the ML-KEM public key is hidden behind the network.
* CPU work is unchanged (the helper runs at a lower priority than the client task and only while
  it is blocked); energy per connection is the same, latency is lower. No concurrency hazard:
  this mbedTLS build has no threading support, and the client waits for the helper right after
  `connect()` returns, so PSA is never used from two tasks at once.
* Auth medians 87 vs 94 are ML-DSA retry variance (same code, same arm settings).

## Run 21 — **headline for the deployment configuration**: same as run 20, quiet network

Same firmware and mode as run 20, re-run on a quiet network (TCP connect medians 19–20 ms,
stalls only around rounds 7–10, 39–41, 63–64, 69–72 and visible in avg/max only).

| Arm | TCP connect | TLS handshake | Hybrid auth | HTTP GET | Full round | ok |
|---|---|---|---|---|---|---|
| **MLKEM+MLDSA+pre** | 20 | **52** | 77 | 41 | **201** | 50/50 |
| MLKEM+MLDSAsign (inline) | 19 | **71** | 75 | 40 | **224** | 50/50 |

```
Precomputed key shares: 50 generated during TCP connect, 50 used, 0 not ready in time (inline fallback); helper stack peak 14040 B
```

### Analysis

* Handshake −19 ms (71 → 52) with the auth and HTTP columns equal between arms: the whole
  difference is the precomputed key share. Full round −23 ms.
* **Deployment configuration — TLS 1.3, X25519MLKEM768, ML-DSA-44 + ECDSA P-256 device
  signature, key share precomputed — 201 ms vs the 266 ms baseline: −65 ms (−24 %).** This
  replaces run 13's 238 ms as the headline number.
* Run 20 (243 vs 262) and run 21 (201 vs 224) agree on the arm-to-arm difference (−19 to −23 ms)
  and differ only in network quality; compare arms within a run.

## Run 22 — **the original firmware, unmodified TLS path, 100 rounds** (`app_legacy/`)

The organisers' original code, taken from the delivered archive and built as `app_legacy/`
(`make flash APP_NAME=app_legacy`). Changes: IPv4 server address (the original parsed IPv6
only), DHCP wait 3 → 15 s, and a wrapper that repeats the original's single
connect + handshake + GET 100 times and times each round with the RTOS tick; rounds after the
first run without the certificate dump so UART output is not inside the timed window. The TLS
path — TLS 1.2 ECDHE-RSA, entropy gathering + DRBG seed on every connection — is untouched.
Same network session as run 21.

```
=== LEGACY benchmark summary: 100 ok, 0 failed ===
                  min   median   avg    max  (ms)
TLS handshake :  121    127    139    454
Full round    :  239    247    266    697
```

### Final comparison — original firmware vs final configuration (runs 22 and 21)

| | Original firmware (run 22, 100 rounds) | Final: TLS 1.3 + X25519MLKEM768 + ML-DSA-44/ECDSA device signature, key share precomputed (run 21, 50 rounds) | Δ |
|---|---|---|---|
| TLS handshake, median | 127 | 52 (+ 77 device signing) | — |
| Full round, median | **247** | **201** | **−46 ms (−19 %)** |
| Full round, average | 266 | 254 | −12 ms |
| Full round, min | 239 | 152 | −87 ms |
| Failed rounds | 0 / 100 | 0 / 50 | |
| Bytes per round (tx / rx) | 464 / 2064 | 4958 / 3249 | +4.5 KB / +1.2 KB |

Two baselines are now on record for the original code: 266 ms (run 1, day one, 15 rounds) and
247 ms median / 266 ms average (run 22, 100 rounds, same session as the final run). Against the
same-session median the final configuration is **−19 %**; against the day-one figure, −24 %.
The average is closer because the final configuration's tail is longer: ML-DSA signing retries
(auth max 294 ms) and the larger request (3.3 KB signature header) stretch the worst rounds,
while the original's tail is network only.

## Run 23 — step 6: dual core, first run (core 1 image stale), 100 rounds

First dual-core run (`EXAMPLE_TLS_MODE=13`: `FINAL 2-core` = deployment configuration +
precompute + ML-DSA signing race with core 1 + ML-KEM decapsulation on core 1, vs `FINAL 1-core`
= the run 21 configuration). Core 1 booted, the self-test passed (sign/verify, abort, race,
decaps) and all 100 rounds succeeded, but the final counters exposed a build bug: core 1's
arena peak read 56 960 B with a 32 KB arena, and 4 "core 1 errors". The Makefile had defined
the core 1 dependency *after* the `build:` rule, so make never ran it and the board carried the
previous core 1 image, whose allocator did not reclaim per-attempt buffers; long signatures ran
out of memory on core 1 and core 0 restarted from scratch (auth tails of 345–512 ms). Medians:
auth 57 vs 97 ms, round 254 vs 289 ms. Superseded by run 24.

**Server change the same morning:** the challenge server's certificate was re-issued at
2026-11-12 08:44 with an ECDSA P-256 key (previously RSA-3072); the handshake now carries
1 941 B from the server instead of 2 885 B, negotiates AES-256-GCM-SHA384, and the client
verifies an ECDSA CertificateVerify (20 ms in software) instead of an RSA one (4.4 ms). Runs
from 23 on are therefore not directly comparable with earlier runs; compare arms within a run.

## Run 24 — step 6: **dual core**, both images rebuilt, four arms' worth of checks, 100 rounds

Same mode 13. Boot and self-test:

```
=== Dual core: starting core 1 (image at 0x000c0000, shared block at 0x20015780) ===
  core 1 ready: ping ok in 0 ms, core 1 clock 150 MHz
=== Dual-core self-test ===
  core 1 signs, core 0 verifies     : PASS  (29 ms wall, 4372700 cycles on core 1, arena peak 9600 B)
  abort while core 1 is signing     : PASS  (parked 0 ms after the request, status 3)
  signing race x3, verified         : PASS  (won by core 0: 1, core 1: 2)
  ML-KEM-768 decaps on core 1       : PASS  (1659036 cycles on core 1)
  hybrid shared secret, core 0 only : 15.096 ms (ML-KEM decaps then X25519)
  hybrid shared secret, two cores   : 11.334 ms (decaps on core 1 || X25519 on core 0)
=== dual-core self-test passed ===
```

| Arm | TCP connect | TLS handshake | Hybrid auth (med / avg / max) | HTTP GET | Full round (med / avg) | ok |
|---|---|---|---|---|---|---|
| **FINAL 2-core** | 22 | **51** | **55 / 63 / 243** | 60 | **201 / 284** | 50/50 |
| FINAL 1-core | 21 | 56 | 60 / 92 / 359 | 59 | 254 / 323 | 50/50 |

```
Dual core: ML-DSA races won by core 0: 30, by core 1: 20 (core 1 aborted 23, both finished 7, core 1 errors 0);
           ML-KEM decaps on core 1: 50 (fallbacks 0); core 1 arena peak 9600 B
ML-DSA working-memory arena on core 0: peak 9600 B of 32768 B
Auth (avg): ML-DSA sign 48.9 ms (2-core) vs 77.7 ms (1-core)
```

Network: stalls in rounds 1–3, 7–9 and 12 (TCP connect up to 1.2 s) inflate avg/max of both
arms equally; medians are clean (TCP connect 21–22 ms).

### Analysis

* **Both cores cooperate on every connection**: 50/50 decapsulations ran on core 1 while core 0
  did X25519 (handshake −5 ms, matching the self-test's 15.1 → 11.3 ms), and 50/50 signatures
  were raced (core 0 won 30, core 1 won 20, no errors; 23 core 1 attempts abandoned within a
  Keccak permutation, 7 finished in the window between core 0 finishing and the abort).
* **The race helps the average and the tail far more than the median**, because signing time
  comes in 23.7 ms attempts: the median case needs two attempts on either arm (55 vs 60 ms), but
  the average ML-DSA signing time drops from 77.7 to 48.9 ms (−29 ms) and the worst auth from
  359 to 243 ms. P(first attempt succeeds) is ≈ 0.27 per core; with two independent racers it is
  ≈ 0.46, which is why the 2-core arm has 22 rounds at ≤ 45 ms against 13 for the 1-core arm.
* **Full round median 201 vs 254 ms (−53 ms, −21 %)** in the same run against the same server:
  the sum of the median gains is only ~10 ms, the rest is the tail of the auth distribution no
  longer landing inside the median round.
* Core 1 executes from the same flash as core 0: its ML-DSA attempt costs the same cycles as on
  core 0 (4.37 M cycles for a 1-attempt signature ≈ 29 ms wall incl. mailbox) but its ML-KEM
  decapsulation is 20 % slower (1.66 M vs 1.38 M cycles), presumably flash-fetch contention.
* Memory: ML-DSA-44 signing with REDUCE_RAM peaks at **9.6 KB** of working memory (measured
  with the arena on both cores) — far below the 44 KB estimate used earlier; core 1 needs 59 KB
  of its 104 KB RAM in total; core 0's static RAM is 298 of 312 KB with the 32 KB arena carved
  from the FreeRTOS heap.

## Comparison (medians)

### Against the agreed baseline (TLS 1.2, seed per connection, clean network: **266 ms**)

| Configuration | Handshake | Auth | Full round | Δ vs baseline |
|---|---|---|---|---|
| TLS 1.2, seed per connection (**baseline**, run 1) | 140 | – | 266 | — |
| TLS 1.2, seed once + lwIP window (run 13) | 134 | – | 182 | −84 ms (−32 %) |
| TLS 1.3 classic, seed once + lwIP window (run 13) | 55 | – | 163 | −103 ms (−39 %) |
| **TLS 1.3 + X25519MLKEM768** (run 13) | 72 | – | **175** | **−91 ms (−34 %)** |
| **TLS 1.3 + X25519MLKEM768 + ML-DSA-44/ECDSA auth, sign only** (run 13) | 71 | 77 | **238** | **−28 ms (−11 %)** |
| same, with self-verify (run 13) | 72 | 94 | 261 | −5 ms (−2 %) |
| TLS 1.3 + X25519MLKEM768 + ML-DSA-**65**/ECDSA auth, with self-verify (run 10) | 77 | 155 | 379 | **+113 ms — target missed** |
| TLS 1.3 + X25519MLKEM768, NTTs on the **PowerQuad** (run 18; CPU-NTT arm of the same run: 179) | 109 | – | 217 | −49 ms, but **+38 ms vs CPU NTT** — negative result |
| **TLS 1.3 + X25519MLKEM768 + ML-DSA-44/ECDSA auth, key share precomputed during TCP connect** (run 21, quiet network; inline arm of the same run: 224) | **52** | 77 | **201** | **−65 ms (−24 %)** — final single-core configuration |
| same + **dual core** (ML-DSA signing race, ML-KEM decaps on core 1) — run 24, new ECDSA server cert; single-core arm of the same run: 254 | 51 | 55 (avg 63) | **201** (1-core arm: 254) | **−53 ms (−21 %) vs single core in the same run**; not comparable to pre-change server runs |

→ **Hybrid post-quantum key establishment *and* hybrid authentication (ML-DSA-44 + ECDSA P-256,
device signing) meet the "no increase in end-to-end latency" goal on the FRDM-MCXN947, without
hardware acceleration of any PQC operation.** ML-DSA-65 does not fit in portable C.

Caveats to state alongside: ML-DSA signing latency is a geometric distribution (budget for the
tail); ECDSA runs in software (ELS/PKC would remove ~10 ms from signing, ~30 ms from
sign+verify); the server certificate is not verified in any arm (`MBEDTLS_SSL_VERIFY_NONE`, as
in the original firmware); the signature is NIST category 2 while the KEM is category 3.

Where the margin came from (all "software support" items, none of them PQC maths):
1. TLS 1.3 instead of TLS 1.2: one round trip fewer (≈ −30 ms on this link).
2. DRBG seeded once instead of per connection: −74 ms of TRNG gathering.
3. lwIP receive window ≥ server first flight: −29 ms on the hybrid arm.

### Earlier (pre-hybrid) comparison

| Configuration | Handshake | Full round | Δ vs baseline |
|---|---|---|---|
| TLS 1.2, seed per connection (baseline, run 1) | 140 | 266 | — |
| TLS 1.2, seed once (run 6) | 143 | 201 | −65 ms |
| TLS 1.3, seed once (run 6) | 55 | **170** | **−96 ms (−36 %)** |

→ **≈ 96 ms of end-to-end latency budget** is available for the post-quantum additions
(ML-KEM key share + encapsulation, ML-DSA certificate + verification) while still meeting
"no increase in end-to-end latency".

### TLS 1.2 vs TLS 1.3, same build

Clean network (runs 1–2, sequential, 15 rounds each, TCP connect ≈ 22 ms both):

| Phase | TLS 1.2 | TLS 1.3 | Δ |
|---|---|---|---|
| TLS handshake | 140 | 55 | −85 ms |
| HTTP GET | 26 | 84 | +58 ms |
| **Full round** | **266** | **237** | **−29 ms (−11 %)** |

Lossy network (run 5, interleaved A/B, 50 rounds each): full round **575 → 501 ms (−13 %)**.
TLS 1.2's extra round trip is one more exposure to retransmission timeouts, so its disadvantage
grows as the link gets worse.

Notes:

* TLS 1.3 needs one round trip fewer, but `mbedtls_ssl_handshake()` also returns one
  round trip earlier (right after the client's Finished). The server's Finished processing and
  its NewSessionTicket messages are then handled inside the first `mbedtls_ssl_read()`, i.e.
  inside the HTTP GET phase. The handshake-only number therefore flatters TLS 1.3; the
  end-to-end round is the fair comparison.
* TLS setup is a constant ~74 ms per connection, independent of protocol version. It is pure
  local work before any byte is sent — a candidate for reclaiming latency budget for PQC.
* The agreed baseline for "no increase in end-to-end latency" is the TLS 1.2 full round:
  **266 ms median** on this network.
