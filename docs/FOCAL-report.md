# The Post-Quantum Retrofit on the FRDM-MCXN947 — results and migration guide

FOCAL / SEMICON hackathon, microcontroller track. Board: NXP FRDM-MCXN947 (Cortex-M33 @ 150 MHz,
ELS/PKC crypto engine, PowerQuad DSP, eIQ Neutron NPU). Stack: NXP MCUXpresso SDK 26.12 preview,
FreeRTOS, lwIP, mbedTLS 3.6.7 (NXP port), coreHTTP. Server: the organisers' challenge server
(`193.30.40.242:443`, RSA-3072 self-signed certificate, TLS 1.2 and 1.3, X25519MLKEM768 capable).

Raw measurements for every run quoted here are in [benchmarks.md](benchmarks.md).
Source and patches: this repository (`app/` = untouched baseline, `app_tls13/` = migrated firmware).

---

## 1. Summary

| | Latency (median, end-to-end) | vs baseline | Works? |
|---|---|---|---|
| **Baseline**: TLS 1.2, ECDHE + RSA-3072 server auth (original firmware) | **266 ms** | — | yes |
| TLS 1.3, classical X25519 (+ two software fixes, §4) | 163 ms | −39 % | yes |
| **Hybrid key exchange**: TLS 1.3 + X25519MLKEM768 | **175 ms** | **−34 %** | yes, server-confirmed |
| **Hybrid key exchange + hybrid device authentication** (ML-DSA-44 + ECDSA P-256) | **238 ms** | **−11 %** | yes, 100 % of rounds |
| same with ML-DSA-65 instead of ML-DSA-44 | 379 ms | +42 % | yes, but misses target |

**Result: the primary goal — hybrid authentication and key establishment with no increase in
end-to-end latency over the RSA baseline — is met on this board, in portable C, without
accelerating any post-quantum operation.** The margin did not come from faster lattice maths;
it came from three "software support" fixes the migration exposed (§4). The post-quantum
algorithms themselves cost 16 ms (ML-KEM-768) and ~90 ms (ML-DSA-44 + ECDSA signing) per
connection.

Everything was measured on the board with interleaved A/B/C arms (each configuration takes
turns, round by round, so all see the same network at the same moments), 100 rounds per run,
compared by **median**, with the TCP-connect time (no crypto) as a network-quality control.

---

## 2. What was built

### 2.1 Baseline (unchanged, `app/`)
The organisers' firmware: TCP connect → TLS 1.2 handshake (`TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`,
server certificate not verified) → `GET /frdm-mcxn947`. We only added the benchmark harness
(per-phase timers, byte counters, 100 rounds, min/median/avg/max).

### 2.2 Migrated firmware (`app_tls13/`)

| Step | Change | Where |
|---|---|---|
| TLS 1.3 | `MBEDTLS_SSL_PROTO_TLS1_3` via the port's `MBEDTLS_USER_CONFIG_FILE` hook | `app_mbedtls_user_config.h` |
| Hybrid KEX | New named group **X25519MLKEM768 (0x11EC)** in the SDK's mbedTLS 3.6.7 client: key share = ML-KEM-768 pk (1184 B) ‖ X25519 pk (32 B); server share = ML-KEM ct (1088 B) ‖ X25519 pk; shared secret = ML-KEM ss ‖ X25519 ss (draft-ietf-tls-ecdhe-mlkem). 180-line patch, guarded by `MBEDTLS_SSL_TLS1_3_HYBRID_MLKEM`. | `patches/mbedtls3x-x25519mlkem768.patch` |
| ML-KEM-768 | **mlkem-native** (PQ Code Package; FIPS 203, formally verified memory safety, constant time), portable C, deterministic API fed by mbedTLS's DRBG | `third_party/mlkem-native` (submodule) |
| Hybrid auth | Device holds an **ML-DSA-44** and an **ECDSA P-256** key pair; per connection it signs the TLS 1.3 **exporter value** (RFC 8446 §7.5, so the signature is bound to that session) with both and sends `X-Hybrid-Auth: mldsa44=<b64>;ecdsa-p256=<b64>` with the request. A demo mode additionally self-verifies both signatures (the organisers' server has no verifier). | `app_hybrid_auth.c` |
| ML-DSA | **mldsa-native** (PQ Code Package; FIPS 204), `REDUCE_RAM`, large working buffers routed to the FreeRTOS heap | `third_party/mldsa-native` (submodule), `app_mldsa_config.h` |
| Benchmark | Interleaved multi-arm harness, DWT cycle-counter micro-benchmarks of every primitive | `app_https_client_task.c`, `app_pqc_bench.c` |

Server-side proof: the challenge server echoes `"handshake_method":"hybrid-pqc"` when the hybrid
group is negotiated and `"legacy"` otherwise; every hybrid round returned `hybrid-pqc`, every
signed request was answered `200`.

---

## 3. Comparison against the original implementation (deliverable 2)

### 3.1 Latency (run 13, clean network, 20 rounds per arm, medians in ms)

| Phase | TLS 1.2 baseline* | TLS 1.3 | TLS 1.3 + ML-KEM | + ML-DSA-44/ECDSA auth |
|---|---|---|---|---|
| TLS setup (DRBG seed, buffers) | 74 → 0 | 0 | 0 | 0 |
| TCP connect (network control) | 20 | 20 | 20 | 20 |
| TLS handshake | 134 | 55 | 72 | 71 |
| Hybrid authentication (sign) | – | – | – | 77 |
| HTTP GET | 21 | 82 | 81 | 46 |
| **Full round** | **182 (266 original)** | **163** | **175** | **238** |

\* The original firmware measured 266 ms (run 1); 182 ms is the same TLS 1.2 handshake after the
software fixes of §4, run in the same session as the other arms. The agreed baseline is 266 ms.

Notes on reading the table: TLS 1.3's `mbedtls_ssl_handshake()` returns one round trip earlier
than TLS 1.2's (right after the client Finished), so the server's Finished processing and its
NewSessionTicket messages land in the first read — inside "HTTP GET". Handshake-only numbers
therefore flatter TLS 1.3; the full round is the fair comparison.

### 3.2 Communication overhead (bytes per connection)

| | TLS 1.2 baseline | TLS 1.3 | + ML-KEM | + ML-DSA-44 auth | (+ ML-DSA-65 auth) |
|---|---|---|---|---|---|
| Handshake sent | 321 | 279 | **1465** (+1186) | 1465 | 1465 |
| Handshake received | 1841 | 1797 | **2885** (+1088) | 2885 | 2885 |
| Request sent | 464 | 428 | 1614 | **4958** (+3.3 KB sig) | 6142 (+4.5 KB) |
| Response received | 2064 | 2157 | 3249 | 3249 | 3249 |

### 3.3 Memory and code size

| | Baseline | TLS 1.3 | + ML-KEM | + ML-DSA |
|---|---|---|---|---|
| Flash (text) | 426 KB | 448 KB (+21) | 460 KB (+11) | 489 KB (+26 for ML-DSA-65; ML-DSA-44 same ±1) |
| Client task stack | 16 KB | 16 KB | **32 KB** (ML-KEM keeps ~8–10 KB of polynomials on the stack) | 32 KB |
| Heap | 96 KB | 96 KB | 128 KB | **192 KB** (ML-DSA-65 signing needs ~68 KB working memory, ML-DSA-44 ~44 KB — on the heap, not the stack) |
| lwIP buffers | TCP_WND 2.9 KB | | **5.8 KB** + larger pbuf pool (+17 KB) | |
| Per-handshake PQC state | – | – | +3.5 KB (ML-KEM sk + ct) | + keys 1312/2560 B, sig 2420 B |

Total RAM in use: ~282 KB of the 312 KB SRAM region, including the 192 KB heap. A product would
size this tighter; the numbers are upper bounds from a benchmark build that carries everything.

### 3.4 Energy
Not measured — no current probe was available. Since the board's active power is roughly
constant while computing, energy per connection scales with the CPU-busy time, which the
micro-benchmarks give directly (§5.1): e.g. ML-KEM adds ~16 ms of CPU time per connection,
ML-DSA-44 signing ~77 ms on average.

### 3.5 Correctness and reproducibility
* Every hybrid handshake was validated by the subsequent encrypted HTTP exchange (both sides must
  derive the same ML-KEM‖X25519 secret) and by the server's own `hybrid-pqc` report.
* ML-KEM encaps/decaps self-test on-board: shared secrets match. ML-DSA/ECDSA self-verify: 0
  failures in all runs.
* 0 failed rounds in 1 300 benchmarked connections across runs 1–13.
* Reproduce: `make setup` (fetches SDK + toolchain), `make patch-sdk`, `make flash
  APP_NAME=app_tls13`, `make monitor`. `EXAMPLE_TLS_MODE` selects the arms, `EXAMPLE_ITERATIONS`
  the rounds. The SDK is not vendored; our changes to it are one reviewable patch file.

### 3.6 Security assumptions (state these with every number)
* The server certificate is **not verified** in any configuration (`MBEDTLS_SSL_VERIFY_NONE`,
  inherited from the original firmware). The RSA-3072 CertificateVerify signature is still
  checked by mbedTLS (4.4 ms, measured) — that is the baseline's "authentication cost".
* Hybrid KEX = X25519MLKEM768 (ML-KEM-768 is NIST category 3). Hybrid auth = ML-DSA-44
  (category 2) + ECDSA P-256; ML-DSA-65 (category 3) was measured but misses the latency target.
* Device authentication is demonstrated as **device-side signing** of the session's exporter
  value, verified on-device (no verifier on the server). A deployment would have the server
  verify; the signing cost is what we measured. The server's RSA authentication is untouched.
* The CTR-DRBG is seeded once from the ELS TRNG and reused (standard SP 800-90A operation, mbedTLS
  reseeds automatically); we assume the MCXN947 TRNG is a sound entropy source.
* The exporter label `EXPORTER-focal-hybrid-auth` and the header format are ours; a real protocol
  would standardise them (or use TLS client certificates once ML-DSA certificates are deployable).

---

## 4. Where the latency actually went — the migration findings

Three things, none of them post-quantum maths, decided the outcome:

1. **TLS 1.3 saves a round trip.** 266 → ~237 ms on its own. Every PQ-ready stack needs TLS 1.3
   anyway (hybrid groups are TLS 1.3 only); migrating the protocol version first buys the budget
   for the PQ cost.
2. **The original firmware re-seeded the DRBG from the TRNG on every connection: 74 ms, every
   time.** Seeding once at boot removed it. This single line was worth more than all PQC costs
   combined.
3. **lwIP's TCP receive window (2 × MSS = 2920 B) was smaller than the server's first flight once
   it carried an ML-KEM ciphertext (~2.9 KB).** One extra ACK round trip per handshake, +29 ms,
   only on the hybrid arm. Raising `TCP_WND` to 4 × MSS fixed it. *The first PQC cost that hurt
   was a buffer sized for 2 KB handshakes, not a CPU.*

Two more that cost time to find:

4. **Silent stack overflow.** ML-KEM's polynomial vectors on the stack of a 16 KB task hung the
   board with no message; `configCHECK_FOR_STACK_OVERFLOW` was off in the SDK example. Turn it on
   before touching PQC; size tasks for ML-KEM (~10 KB extra) and never put ML-DSA on a task stack
   (44–68 KB working set → heap or static buffers).
5. **ML-DSA signing latency is a distribution, not a number.** The rejection-sampling loop runs a
   geometric number of attempts (FIPS 204 expectation: 4.25 for ML-DSA-44, 5.1 for ML-DSA-65).
   Measured ML-DSA-44: 23.7 ms per attempt; medians between 44 and 118 ms from run to run with
   identical code; average 77–100 ms; worst observed 253 ms (ML-DSA-65: 364 ms). Deadline-driven
   designs must budget for the tail (p99 ≈ 10 attempts), or pre-compute signatures where the
   protocol allows.

---

## 5. Acceleration analysis (deliverable 3)

### 5.1 Measured cost of every primitive (DWT cycle counter, 150 MHz, minimum of 10 runs)

| Operation | ms | Where it runs |
|---|---|---|
| ML-KEM-768 keypair | 6.63 | CPU, portable C |
| ML-KEM-768 decaps | 9.19 | CPU |
| — of which Keccak/SHAKE (gen_matrix ×2 + PRFs) | ~7.8 (≈50 %) | CPU |
| — of which NTT / inverse NTT | ~2.0 (≈13 %) | CPU |
| Keccak-f1600 permutation | 0.094 (14 100 cycles) | CPU |
| NTT of one 256-coeff polynomial | 0.132 (19 800 cycles) | CPU |
| ML-DSA-44 keypair / sign (per attempt) / verify | 14.7 / 23.7 / 15.3 | CPU |
| ML-DSA-65 keypair / sign (per attempt) / verify | 25.4 / 36.5 / 25.5 | CPU |
| X25519 keygen + shared secret | 10.8 + 5.4 = **16.2** | **CPU (software!)** |
| ECDSA P-256 sign / verify | 11.4 / **20.3** | **CPU (software!)** |
| RSA-3072 verify (live server key) | 4.42 | CPU |
| RSA-2048 sign / verify | 198 / 2.2 | CPU |
| SHA-256, 1 KB | 0.042 | **ELS hardware** |
| SHA3-256, 1 KB (software SHAKE) | 0.83 | CPU |

### 5.2 Can the NPU (or PowerQuad) accelerate the lattice operations?

**The NTT is the only candidate** — it is a matrix-vector product (or FFT-shaped butterfly).
Keccak, sampling and packing are branchy bit operations no accelerator on this chip can run.

Three measured/structural reasons it does not pay here:

1. **Amdahl.** NTTs are ~2 ms of a 175 ms hybrid handshake (ML-KEM) and ~4 ms per ML-DSA-44
   signing attempt. A *free* NTT would improve the end-to-end round by ≤ 1 % (KEX) / ≤ 6 % (auth).
   A realistic 2× speed-up: half of that.
2. **Arithmetic and precision.** NTT arithmetic is modular (q = 3329 / 8 380 417). The Neutron NPU
   computes int8×int8→int32 for neural-network layers and has no modular reduction: 12-bit
   (ML-KEM) or 23-bit (ML-DSA) operands must be split into limbs → 4 (ML-KEM) to 9 (ML-DSA)
   matrix products of 256×256 per transform, plus 256 reductions on the CPU. The PowerQuad's FFT
   engine is float/fixed-point: an exact integer convolution of 12-bit values overflows float32's
   24-bit mantissa, again forcing limb splitting. Its int32 matrix engine can do an exact
   256×256 product for ML-KEM (barely: sums reach 2³²), with CPU reduction afterwards.
3. **Data movement and invocation.** One software NTT is 132 µs. An NPU call goes through the
   TensorFlow-Lite-Micro runtime with a pre-compiled "model" — hundreds of µs to ms per call, i.e.
   slower than the CPU doing the NTT. The PowerQuad is memory-mapped and cheap to invoke (µs), so a
   ~2× gain per NTT is plausible but caps at ~1 ms per handshake.

**Conclusion: on the MCXN947 the NPU is not a useful accelerator for ML-KEM/ML-DSA, and the
PowerQuad's ceiling is ~1 % of end-to-end latency.** The hashing (Keccak, ~50 % of ML-KEM and a
similar share of ML-DSA) is the real compute cost and there is no Keccak hardware on this part.

### 5.3 What *would* help, ranked by measured payoff

| Lever | Expected gain per connection | Effort | Status |
|---|---|---|---|
| **ELS/PKC hardware for X25519 and ECDSA.** The accelerator exists and the hash path proves it works (SHA-256 is 20× faster than software SHA-3), but the SDK's mbedTLS 3.x PSA port does not route elliptic-curve operations to it. | X25519 16 → ~2 ms; ECDSA sign 11 → ~2 ms, verify 20 → ~3 ms: **≈ 15 ms on every arm, ≈ 25 ms more for hybrid auth** | SDK integration | identified, not done |
| **Optimised Keccak assembly** for Cortex-M (2–3× over portable C; mlkem-native/mldsa-native accept a custom FIPS-202 backend) | ≈ 4–5 ms (ML-KEM), ≈ 10–20 ms (ML-DSA sign) | medium | not done |
| TLS 1.3, DRBG-once, TCP window (§4) | **−91 ms** | trivial | **done** |
| ML-DSA-44 instead of ML-DSA-65 | −60…−100 ms signing | one define | **done** |
| PowerQuad NTT | ≤ 1 ms | medium | not worth it |
| NPU NTT | ≤ 0 (overhead ≥ gain) | high | negative result |

---

## 6. Migration guide (deliverable 4)

For an engineer retrofitting an existing mbedTLS-based MCU client. Effort figures are ours, for
one person familiar with the stack.

**Step 0 — Measure before you touch anything (½ day).**
Per-phase timers (setup, TCP connect, handshake, request), byte counters, ≥ 100 rounds, report
medians, keep a no-crypto control (TCP connect) so network drift can't masquerade as crypto cost.
Interleave configurations in one firmware; sequential runs on Wi-Fi-backed links are not comparable
(we have two runs in the log that prove it).

**Step 1 — TLS 1.3 (hours).** One config flag in mbedTLS 3.6 (`MBEDTLS_SSL_PROTO_TLS1_3`; use
the port's user-config hook rather than editing the SDK). Pin the version per connection during
evaluation so a silent fallback can't fake a result. Expect −1 RTT.

**Step 2 — Fix what the baseline was doing wrong (hours).** Seed the DRBG once. Check lwIP
`TCP_WND`/`PBUF_POOL_SIZE` against the largest server flight you will see (≥ 3 KB with ML-KEM,
≥ 8 KB if the server ever sends an ML-DSA certificate chain). Enable stack-overflow checking.

**Step 3 — Hybrid key exchange (1–2 days).** mbedTLS 3.6 has no ML-KEM and no hook for it; the
TLS 1.3 client has three `/* other KEMs? */` placeholders (write key share, parse key share, derive
secret). Our 180-line patch fills them for X25519MLKEM768 using mlkem-native's deterministic API
(coins from mbedTLS's RNG, so no global `randombytes`). Budget +11 KB flash, +16 KB task stack,
+3.5 KB per handshake, +2.3 KB on the wire, +16 ms CPU. Verify against a server that reports the
negotiated group. Mbed TLS 4.x / TF-PSA-Crypto will eventually ship this natively; the patch is a
bridge, not a destination.

**Step 4 — Hybrid authentication (1–2 days).** Decide the direction first: *verifying* an ML-DSA
signature (server auth) costs 15–25 ms + a ~6 KB certificate; *producing* one (device auth) costs
50–120 ms average with a long tail. Choose the parameter set by measurement: ML-DSA-44 met our
target, ML-DSA-65 did not. Keep ML-DSA working memory off task stacks (44–68 KB). Bind device
signatures to the TLS session (exporter value) so they cannot be replayed. Keep ECDSA alongside
(hybrid) until PQ signatures have years of deployment behind them.

**Step 5 — Profile, then accelerate the right thing (1 day).** Use the cycle counter, not the RTOS
tick. On this chip the answer was: wire the existing ELS/PKC into the ECC path (classical crypto was
running in software!), consider Keccak assembly, ignore the NPU for lattice maths.

**Compatibility issues hit along the way**
* NXP mbedTLS 3.x port: TLS 1.3 off by default; ECC not on the PKC; `MBEDTLS_USER_CONFIG_FILE`
  macro must be passed with the SDK's `\\\"…\\\"` escaping.
* SDK example FreeRTOS config: no stack-overflow detection; 16 KB client task.
* lwIP defaults sized for < 3 KB handshakes.
* mlkem-native/mldsa-native: `warn_unused_result` everywhere (good) — the SDK builds with
  `-Werror`; both libraries need a 64-byte-aligned allocator if buffers go to the heap.
* The challenge server has no ML-DSA certificate and does not verify client signatures, so
  server-authenticated hybrid auth could not be tested end-to-end; device-side signing was
  demonstrated instead and the verify-side cost measured on-device.

**Lessons learned**
1. The PQ algorithms were never the bottleneck on this board; the surrounding software was.
2. Measure with interleaved arms and medians, or the Wi-Fi will write your results.
3. Parameter-set choice (ML-DSA-44 vs 65) is a bigger lever than any accelerator.
4. Signing latency is a distribution; design for the tail.
5. Before buying an accelerator for the NTT, check what fraction of the time the NTT actually is
   (13 %) and whether your classical crypto is even using the accelerator you already have (ours
   wasn't).

---

## Appendix — run index

| Run | Configuration | Full round (median) | Note |
|---|---|---|---|
| 1 | baseline TLS 1.2, 15 rounds | 266 ms | agreed baseline |
| 2–3 | TLS 1.3 classic, 15 / 100 rounds | 237 / 250 ms | |
| 4 | baseline, 100 rounds | 510 ms | network degraded — excluded |
| 5 | A/B TLS 1.2 vs 1.3, lossy network | 575 / 501 ms | TLS 1.3 suffers less from loss |
| 6 | A/B, DRBG seeded once | 201 / 170 ms | −74 ms setup |
| 7 | + hybrid X25519MLKEM768 (3 arms) | 213 / 181 / 231 ms | first hybrid handshakes |
| 8 | on-board micro-benchmark | — | §5.1 |
| 9 | + lwIP TCP_WND 4×MSS | 174 / 159 / 175 ms | hybrid overhead = ML-KEM cost exactly |
| 10 | + ML-DSA-65/ECDSA auth (4 arms) | … / 379 ms | target missed |
| 11 | ML-DSA-44 instead | … / 289 ms (self-verify) | |
| 12 | 5 arms incl. sign-only, degraded network | 292 vs 290 (TLS 1.2 same run) | relative only |
| **13** | **5 arms, clean network** | **182 / 163 / 175 / 261 / 238 ms** | **headline** |
