/* Direct blocking puts release their source before remote synchronization.
 * See ofi_transmit_complete.md for the required OFI configuration. */
#include <shmem.h>
#include <shmemx.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BYTES (128 * 1024)
#define WRITES 17

static void
check(const unsigned char *target, unsigned char value)
{
    for (size_t i = 0; i < BYTES; i++) {
        if (target[i] != value) {
            fprintf(stderr, "PE %d: incorrect payload at %zu\n", shmem_my_pe(), i);
            shmem_global_exit(1);
        }
    }
}

int
main(int argc, char **argv)
{
    int transmit_required = !(argc == 2 &&
                             strcmp(argv[1], "--delivery-fallback") == 0);
    /* Match the library's SHMEM_ precedence and SMA_ alias.  With the
     * optimization disabled, delivery may complete before explicit quiet. */
    const char *transmit_env = getenv("SHMEM_OFI_TRANSMIT_COMPLETE");
    if (transmit_env == NULL)
        transmit_env = getenv("SMA_OFI_TRANSMIT_COMPLETE");
    if (transmit_env != NULL && strtol(transmit_env, NULL, 0) == 0)
        transmit_required = 0;
    shmem_init();
    int me = shmem_my_pe();
    int npes = shmem_n_pes();
    if (npes < 2)
        shmem_global_exit(1);
    unsigned char *target = shmem_malloc(WRITES * BYTES);
    unsigned char *source = malloc(BYTES);
    long *ready = shmem_malloc(sizeof(*ready));
    uint64_t *signal = shmem_malloc(sizeof(*signal));
    shmem_ctx_t ctx;
    if (!target || !source || !ready || !signal ||
        shmem_ctx_create(SHMEM_CTX_PRIVATE, &ctx))
        shmem_global_exit(1);
    memset(target, 0, WRITES * BYTES);
    *ready = 0;
    *signal = 0;
    shmem_barrier_all();

    /* A return followed by immediate source overwrite must preserve payload.
     * Delivery statistics must advance only at explicit synchronization. */
    if (me == 0) {
        uint64_t before, issued, completed;
        shmemx_pcntr_get_completed_write(ctx, &before);
        for (int i = 0; i < WRITES; i++) {
            memset(source, i + 1, BYTES);
            for (int pe = 1; pe < npes; pe++)
                shmem_ctx_putmem(ctx, target + i * BYTES, source, BYTES, pe);
            memset(source, 0xee, BYTES);
        }
        shmemx_pcntr_get_issued_write(ctx, &issued);
        shmemx_pcntr_get_completed_write(ctx, &completed);
        if (issued <= before || (transmit_required && completed != before))
            shmem_global_exit(1);
        shmem_ctx_quiet(ctx);
        shmemx_pcntr_get_completed_write(ctx, &completed);
        if (completed != issued)
            shmem_global_exit(1);
        shmem_ctx_quiet(ctx); /* Empty synchronization. */
    }
    shmem_barrier_all();
    if (me != 0)
        for (int i = 0; i < WRITES; i++)
            check(target + i * BYTES, i + 1);
    shmem_barrier_all();

    /* Fence must order a direct payload before an ordinary notification.
     * Check before a barrier can hide an early notification. */
    if (me == 0) {
        memset(source, 42, BYTES);
        shmem_ctx_putmem(ctx, target, source, BYTES, 1);
        memset(source, 0xee, BYTES);
        shmem_ctx_fence(ctx);
        shmem_ctx_long_p(ctx, ready, 1, 1);
        shmem_ctx_quiet(ctx);
    } else if (me == 1) {
        shmem_long_wait_until(ready, SHMEM_CMP_EQ, 1);
        check(target, 42);
    }
    shmem_barrier_all();

    /* Zero-byte put-with-signal follows a separate internal binding. */
    if (me == 0) {
        memset(source, 47, BYTES);
        shmem_ctx_putmem(ctx, target, source, BYTES, 1);
        memset(source, 0xee, BYTES);
        shmem_ctx_putmem_signal_nbi(ctx, target, source, 0,
                                   signal, 2, SHMEM_SIGNAL_SET, 1);
        shmem_ctx_quiet(ctx);
    } else if (me == 1) {
        shmem_signal_wait_until(signal, SHMEM_CMP_EQ, 2);
        check(target, 47);
    }
    shmem_barrier_all();

    /* NBI source lifetime stays tied to quiet, and mixes with direct puts. */
    if (me == 0) {
        memset(source, 43, BYTES);
        shmem_ctx_putmem_nbi(ctx, target + BYTES, source, BYTES, 1);
        shmem_ctx_putmem(ctx, target, source, BYTES, 1);
        shmem_ctx_quiet(ctx);
        memset(source, 0xee, BYTES);
    }
    shmem_barrier_all();
    if (me == 1) {
        check(target, 43);
        check(target + BYTES, 43);
    }
    shmem_barrier_all();

    /* Put-with-signal must also order earlier direct-endpoint payloads. */
    if (me == 0) {
        memset(source, 44, BYTES);
        shmem_ctx_putmem(ctx, target, source, BYTES, 1);
        memset(source, 45, BYTES);
        shmem_ctx_putmem_signal_nbi(ctx, target + BYTES, source, BYTES,
                                   signal, 1, SHMEM_SIGNAL_SET, 1);
        shmem_ctx_quiet(ctx);
    } else if (me == 1) {
        shmem_signal_wait_until(signal, SHMEM_CMP_EQ, 1);
        check(target, 44);
        check(target + BYTES, 45);
    }
    shmem_barrier_all();

    /* The default context must use the same source-lifetime guarantee. */
    if (me == 0) {
        memset(source, 46, BYTES);
        shmem_putmem(target, source, BYTES, 1);
        memset(source, 0xee, BYTES);
        shmem_quiet();
    }
    shmem_barrier_all();
    if (me == 1)
        check(target, 46);
    shmem_barrier_all();

    shmem_ctx_destroy(ctx);
    free(source);
    shmem_free(signal);
    shmem_free(ready);
    shmem_free(target);
    shmem_finalize();
    return 0;
}
