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

## Comparison (medians)

### Against the agreed baseline (TLS 1.2, seed per connection, clean network: **266 ms**)

| Configuration | Handshake | Full round | Δ vs baseline |
|---|---|---|---|
| TLS 1.2, seed per connection (baseline, run 1) | 140 | 266 | — |
| TLS 1.3 classic, seed once (run 7) | 61 | 181 | −85 ms (−32 %) |
| **TLS 1.3 + X25519MLKEM768, seed once (run 7)** | 102 | **231** | **−35 ms (−13 %)** |

→ **Hybrid post-quantum key establishment meets the "no increase in end-to-end latency" goal
on this board without any hardware acceleration.** The remaining budget (~35 ms) plus whatever
acceleration recovers from the 41 ms ML-KEM cost is what hybrid *authentication* (ML-DSA) will
have to fit into.

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
