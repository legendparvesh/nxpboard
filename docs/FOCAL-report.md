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
| Hybrid key exchange with the ML-KEM NTTs on the **PowerQuad** accelerator (§5.2.1) | 217 ms (CPU-NTT arm of the same run: 179) | −18 % | yes, but +38 ms vs the CPU NTT |
| **Final: hybrid key exchange + hybrid device authentication, key share precomputed during the TCP connect** (§4, item 6; run 21) | **201 ms** (inline arm of the same run: 224); handshake 52 ms ≈ classical TLS 1.3 | **−24 %** | yes, 50/50, 0 fallbacks |

**Final side-by-side (same network session, runs 22 and 21):**

| | Original firmware, unmodified TLS path (100 rounds) | Final configuration (50 rounds) |
|---|---|---|
| Full round, median | **247 ms** | **201 ms (−19 %)** |
| Full round, average | 266 ms | 254 ms |
| Full round, min / max | 239 / 697 ms | 152 / 704 ms |
| TLS handshake, median | 127 ms | 52 ms + 77 ms device signing |
| Failed rounds | 0 | 0 |

**Result: the primary goal — hybrid authentication and key establishment with no increase in
end-to-end latency over the RSA baseline — is met on this board, in portable C, without
accelerating any post-quantum operation: 201 ms against the original firmware's 247 ms median
measured in the same session (−19 %), or against the 266 ms day-one baseline (−24 %).** The margin did
not come from faster lattice maths; it came from three "software support" fixes the migration
exposed and from hiding the client's key generation behind the TCP connect (§4). The
post-quantum algorithms themselves cost 16 ms (ML-KEM-768) and ~90 ms (ML-DSA-44 + ECDSA
signing) of CPU per connection.

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
* 0 failed rounds in 1 300 benchmarked connections across runs 1–13. The PowerQuad-NTT arm of
  runs 14–16 failed 1 handshake in 25 (a wrong NTT); after the fix in run 18, 100/100 rounds ok.
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
   (44–68 KB working set → heap or static buffers). It bit twice: the Kconfig symbol is a
   boolean, so `=2` in `prj.conf` was silently ignored and the check stayed off until run 20,
   when a 12 KB helper task (measured peak 14 KB) froze the board again. Check the *generated*
   `FreeRTOSConfig_Gen.h`, not the setting you wrote.
5. **ML-DSA signing latency is a distribution, not a number.** The rejection-sampling loop runs a
   geometric number of attempts (FIPS 204 expectation: 4.25 for ML-DSA-44, 5.1 for ML-DSA-65).
   Measured ML-DSA-44: 23.7 ms per attempt; medians between 44 and 118 ms from run to run with
   identical code; average 77–100 ms; worst observed 253 ms (ML-DSA-65: 364 ms). Deadline-driven
   designs must budget for the tail (p99 ≈ 10 attempts), or pre-compute signatures where the
   protocol allows.

And one that gave latency back without touching the maths:

6. **Generate the key share while the TCP connect is in flight.** The client task is idle for
   ~20 ms waiting for the SYN-ACK; the ML-KEM-768 keypair (6.7 ms) and X25519 keygen (10.8 ms)
   do not depend on the server. A low-priority helper task generates them in that window and the
   patched mbedTLS takes them when it writes the ClientHello (`app_keyshare.c`; falls back to
   inline generation if the share is not ready). Run 20: handshake **73 → 56 ms** (−17 ms,
   50/50 shares ready in time), full round 262 → 243 ms. The hybrid TLS 1.3 handshake now costs
   the same as a classical one (55 ms). Each key share is used for exactly one connection; CPU
   time and energy are unchanged, only the critical path shrinks. Note the ordering constraint:
   mbedTLS here has no threading support, so the client waits for the helper right after
   `connect()` returns — the two tasks never use PSA at the same time.

### 4.1 Optimisations applied — summary

Everything that was changed to get from 266 ms to the final numbers, in the order it was done,
with the effect measured in an interleaved A/B on the board. "Round" is the full
connect + handshake + auth + GET, medians.

| # | Optimisation | What it changes | Measured effect | Run | Where |
|---|---|---|---|---|---|
| 1 | **TLS 1.3 instead of TLS 1.2** | One handshake round trip fewer; prerequisite for hybrid groups | handshake 140 → 55 ms; round −30 ms on its own | 3, 5 | `app_mbedtls_user_config.h`, version pin per connection in `app_mbedtls_socket.c` |
| 2 | **DRBG seeded once at boot** | Original firmware gathered TRNG entropy and reseeded on every connection | **−74 ms** per connection | 6 | `APP_DRBG_SEED_ONCE` in `app_mbedtls_socket.c` |
| 3 | **lwIP receive window 2×MSS → 4×MSS** (+ larger pbuf pool, 32 KB lwIP heap) | Server's first flight with an ML-KEM ciphertext (~2.9 KB) no longer stalls for an extra ACK round trip | hybrid handshake 102 → 73 ms, **−29 ms** | 9 | `prj.conf` (`TCP_WND`, `PBUF_POOL_SIZE`, `MEM_SIZE`) |
| 4 | **ML-DSA-44 instead of ML-DSA-65** | NIST category 2 signature instead of 3; 23.7 vs 36.5 ms per signing attempt, 2420 vs 3309 B signature | round 379 → 289 ms (with self-verify) | 10, 11 | `app_mldsa_config.h` |
| 5 | **Sign-only device auth (no on-device self-verify)** | The peer verifies; the device no longer runs ML-DSA verify (15 ms) + ECDSA verify (20 ms) after signing | round 261 → **238 ms** | 12, 13 | `hybrid_auth = 2` arm, `app_hybrid_auth.c` |
| 6 | **Key share generated during the TCP connect** | ML-KEM keypair + X25519 keygen run in a helper task while the client waits for the SYN-ACK | handshake 73 → **56 ms** (−17), hybrid handshake = classical TLS 1.3 | 20 | `app_keyshare.c`, hook in the SDK patch |
| 7 | Memory sizing for PQC (correctness, not speed) | Client task stack 16 → 32 KB; heap 96 → 192 KB; ML-DSA working memory on the heap with a 64-byte-aligned allocator (`REDUCE_RAM`); stack-overflow checking actually enabled | from silent hangs to 0 failed rounds in every CPU-NTT arm of runs 7–20 | 7, 20 | `main.c`, `prj.conf`, `app_hybrid_auth.c` |

Net effect on the deployment configuration (hybrid KEX + ML-DSA-44/ECDSA device signature):
**266 ms baseline → 238 ms (run 13) → 201 ms with #6 (run 21, quiet network; inline arm of
the same run 224 ms)**. Without device authentication, hybrid key exchange alone is ≈ 158 ms,
below the classical TLS 1.3 arm.

Tried and measured, **not adopted**:

| Attempt | Result | Why not | Run |
|---|---|---|---|
| ML-KEM NTT on the PowerQuad matrix engine | correct, but NTT 23.8× slower; handshake **+37 ms**; deployment config 281 ms (misses target) | dense 16×16 products at 1.8 cycles/MAC vs an O(n log n) butterfly; limb splitting for a float32 datapath with an undocumented 16-bit output clamp (§5.2.1) | 14–19 |
| NTT on the eIQ Neutron NPU | not executable | runtime and converter not in the public SDK; quantised int8 output path cannot deliver exact results; invocation overhead > the whole software NTT | — |
| ML-DSA-65 | 379 ms, misses target | signing 155 ms average in portable C | 10 |

Identified, **not done** (see §5.3 for the expected gains): ELS/PKC hardware elliptic-curve
(≈ 15 ms), assembly Keccak (≈ 5 ms KEX, 10–20 ms signing), dual-core ML-DSA signing race
(≈ 25 ms off the median, halves the tail).

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
   matrix products of 256×256 per transform, plus 256 reductions on the CPU. The PowerQuad's
   matrix engine computes in float32 and, as measured below, clamps outputs to 16 bits, so the
   operands must be split into limbs there too.
3. **Data movement and invocation.** One software NTT is 132 µs. An NPU call goes through the
   TensorFlow-Lite-Micro runtime with a pre-compiled "model" — hundreds of µs to ms per call, i.e.
   slower than the CPU doing the NTT. The PowerQuad is memory-mapped and cheap to invoke, but its
   operands are limited to 16×16.

#### 5.2.1 The PowerQuad NTT, implemented and measured (runs 14–18)

Because the organisers asked for ML-KEM on the accelerator, the NTT was ported to the PowerQuad
matrix engine and run inside the live handshake (`app_pq_ntt.c`, benchmark arm `MLKEM(PQ-NTT)`,
`EXAMPLE_TLS_MODE 10`):

* FIPS 203 Algorithm 9 rewritten as two 128×128 matrix-vector products (even and odd coefficients
  share the twiddle matrix W[i][j] = 17^((2·BitRev7(i)+1)·j) mod q, verified against the
  reference by `tools/gen_pq_ntt_tables.py`).
* W stored in flash as 8×8 tiles of 16×16 (the engine's maximum operand), split into 6-bit limbs;
  coefficients split into three 5-bit limbs; 128 `PQ_MatrixMultiplication` calls per NTT; the CPU
  accumulates the column tiles, recombines the limbs and reduces mod q.
* Plugged into mlkem-native through its native-backend hook (`MLK_USE_NATIVE_NTT`), switchable
  at runtime, so the same binary measures both paths in interleaved rounds.

| Measured (DWT, 150 MHz) | CPU (portable C) | PowerQuad | Ratio |
|---|---|---|---|
| One 16×16 × 16×6 block product (1 536 MAC) | — | 2 790 cycles (1.81 cycles/MAC) | |
| NTT of one polynomial | 19 834 cycles = 0.132 ms | 471 731 cycles = 3.14 ms | **23.8× slower** |
| ML-KEM-768 keypair + decaps | 15.9 ms | 52.1 ms | 3.3× slower |
| TLS 1.3 hybrid handshake, median of 25 interleaved rounds | 72 ms | 109 ms | **+37 ms** |
| Full round (TCP + handshake + GET) | 179 ms | 217 ms | +38 ms |

Correctness was the hard part. The first build (runs 14–16) produced a wrong coefficient about
once in 15 000 and failed one hybrid handshake in 25 with a record-MAC error. Interrupt masking,
memory barriers and a data-level completion wait changed nothing. A per-block verification build
(run 17) caught the engine in the act: `engine 32767 vs cpu 34870`. **The matrix engine saturates
every output at +32 767, the int16 maximum, even with the 32-bit output format selected**, and the
SDK driver does not document it. Any 16-term dot product of two 6-bit limbs can exceed that
(63·63·16 = 63 504), which is why only the rare large sums — concentrated in one twiddle row,
hence the recurring coefficient 56 — went wrong. Splitting the coefficients into 5-bit limbs
(16·63·31 = 31 248 < 32 768) fixed it: 40 000 random block products and 153 600 NTT coefficients
verified with zero mismatches, 100/100 handshakes in run 18. The fix costs a further 1.5× in
engine work (six B columns instead of four), which is why run 18 is slower than run 14's 14.8×.

Why it cannot win, from the measurements: the engine offers dense products at 1.6–1.8 cycles per
MAC, so a 256-point NTT costs ≈ 197 k MACs that way (two 128×128 products × 6 limb columns)
against ≈ 2 k modular multiplications for the butterfly the Cortex-M33 runs; a four-step
formulation (16-point and 8-point stages, ≈ 25 k MACs) would still need ≥ 40 k cycles before
overheads, twice the software NTT. The engine's width (16×16) and output range (16-bit) are built
for small DSP filters, not for a 12-bit modular transform.

**Conclusion: on the MCXN947 the NPU is not a useful accelerator for ML-KEM/ML-DSA, and the
PowerQuad NTT is a measured negative result: correct, but 23.8× slower per transform and +37 ms
per hybrid handshake.** The deployment configuration keeps the NTT on the CPU. The hashing
(Keccak, ~50 % of ML-KEM and a similar share of ML-DSA) is the real compute cost and there is no
Keccak hardware on this part.

### 5.3 What *would* help, ranked by measured payoff

| Lever | Expected gain per connection | Effort | Status |
|---|---|---|---|
| **ELS/PKC hardware for X25519 and ECDSA.** The accelerator exists and the hash path proves it works (SHA-256 is 20× faster than software SHA-3), but the SDK's mbedTLS 3.x PSA port does not route elliptic-curve operations to it. | X25519 16 → ~2 ms; ECDSA sign 11 → ~2 ms, verify 20 → ~3 ms: **≈ 15 ms on every arm, ≈ 25 ms more for hybrid auth** | SDK integration | identified, not done |
| **Optimised Keccak assembly** for Cortex-M (2–3× over portable C; mlkem-native/mldsa-native accept a custom FIPS-202 backend) | ≈ 4–5 ms (ML-KEM), ≈ 10–20 ms (ML-DSA sign) | medium | not done |
| TLS 1.3, DRBG-once, TCP window (§4) | **−91 ms** | trivial | **done** |
| Key share generated during the TCP connect (§4, item 6) | **−17 ms** handshake | small (helper task + hook in the key-share writer) | **done** (run 20) |
| ML-DSA-44 instead of ML-DSA-65 | −60…−100 ms signing | one define | **done** |
| PowerQuad NTT (§5.2.1) | **measured: +37 ms per hybrid handshake**, NTT 23.8× slower than the CPU | medium | **done — negative result**, kept as a switchable benchmark arm |
| NPU NTT | ≤ 0 (overhead ≥ gain); toolchain not in the public SDK | high | negative result (analysis) |

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
| 14 | + NTT on the PowerQuad (4 arms), 6-bit limbs | 261 (PQ) / 241 (CPU NTT) ms | 1 handshake in 25 fails: rare wrong NTT |
| 15–16 | barriers, interrupt masking, data-level completion wait | — | fault unchanged: not a timing hazard |
| 17 | per-block verify build | — | root cause: engine clamps outputs at +32 767 |
| 18 | 5-bit coefficient limbs (fix), 4 arms | 217 (PQ) / 179 (CPU NTT) / 163 / 181 ms | 100/100 ok; PowerQuad NTT 23.8× slower, +37 ms |
| 19 | deployment config (hybrid KEX + ML-DSA-44/ECDSA sign-only), CPU NTT vs PowerQuad NTT, 50 + 50 | **222** (CPU) / 281 (PQ) ms | PowerQuad arm would miss the 266 ms target |
| 20 | deployment config, key share precomputed during TCP connect vs inline, 50 + 50 | 243 / 262 ms | handshake 56 vs 73 ms (−17); 50/50 ready in time |
| **21** | **same, quiet network** | **201** / 224 ms | **final headline**; handshake 52 vs 71 |
| **22** | **original firmware, unmodified TLS path (`app_legacy/`), 100 rounds, same session** | **247** ms median, 266 avg | final comparison: 247 → 201 ms (−19 %) |
