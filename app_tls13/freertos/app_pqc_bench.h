#ifndef APP_PQC_BENCH_H
#define APP_PQC_BENCH_H

/* Runs the on-board crypto micro-benchmark (ML-KEM-768 and its building blocks,
 * X25519, ECDSA P-256, SHA-256 vs SHA-3) and prints a cycle/µs table.
 * Call from a task with >= 16 KB stack; buffers come from the heap. */
void app_pqc_bench_run(void);

#endif /* APP_PQC_BENCH_H */
