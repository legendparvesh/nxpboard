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

## Comparison (medians)

### Against the agreed baseline (TLS 1.2, seed per connection, clean network: **266 ms**)

| Configuration | Handshake | Full round | Δ vs baseline |
|---|---|---|---|
| TLS 1.2, seed per connection (baseline, run 1) | 140 | 266 | — |
| TLS 1.2, seed once + lwIP window (run 9) | 132 | 174 | −92 ms (−35 %) |
| TLS 1.3 classic, seed once + lwIP window (run 9) | 55 | 159 | −107 ms (−40 %) |
| **TLS 1.3 + X25519MLKEM768, seed once + lwIP window (run 9)** | 73 | **175** | **−91 ms (−34 %)** |

→ **Hybrid post-quantum key establishment meets the "no increase in end-to-end latency" goal
on this board, by a wide margin, without any hardware acceleration.** The ~90 ms margin is the
budget for hybrid *authentication* (ML-DSA verify + ~6 KB certificate).

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
