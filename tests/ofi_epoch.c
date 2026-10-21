/* Public-API regression for OFI large-write epochs; see ofi_epoch.md. */
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
main(void)
{
    const char *epoch_env = getenv("SHMEM_OFI_EPOCH_SYNC");
    if (epoch_env == NULL)
        epoch_env = getenv("SMA_OFI_EPOCH_SYNC");
    int epoch_enabled = epoch_env == NULL || strtol(epoch_env, NULL, 10) != 0;
    shmem_init();
    int me = shmem_my_pe();
    int npes = shmem_n_pes();
    if (npes < 3)
        shmem_global_exit(1);

    unsigned char *target = shmem_malloc(WRITES * BYTES);
    unsigned char *source = malloc(WRITES * BYTES);
    long *ready = shmem_malloc(sizeof(*ready));
    long *reply = shmem_malloc(sizeof(*reply));
    uint64_t *signal = shmem_malloc(sizeof(*signal));
    shmem_ctx_t ctx, direct_ctx;
    if (!target || !source || !ready || !reply || !signal ||
        shmem_ctx_create(SHMEM_CTX_PRIVATE | SHMEMX_CTX_BOUNCE_BUFFER, &ctx) ||
        shmem_ctx_create(SHMEM_CTX_PRIVATE, &direct_ctx))
        shmem_global_exit(1);
    memset(target, 0, WRITES * BYTES);
    *ready = *reply = 0;
    *signal = 0;
    shmem_barrier_all();

    /* Keep all NBI sources alive until quiet; cover several destinations. */
    if (me == 0) {
        uint64_t completed_before, completed_after, issued;
        shmemx_pcntr_get_completed_write(ctx, &completed_before);
        for (int i = 0; i < WRITES; i++) {
            memset(source + i * BYTES, i + 1, BYTES);
            for (int pe = 1; pe < npes; pe++)
                shmem_ctx_putmem_nbi(ctx, target + i * BYTES,
                                    source + i * BYTES, BYTES, pe);
        }
        /* With OFI epoch routing, fence must leave bulk completion pending.
         * These counters advance only when the epoch is synchronized. */
        shmemx_pcntr_get_issued_write(ctx, &issued);
        shmem_ctx_fence(ctx);
        shmemx_pcntr_get_completed_write(ctx, &completed_after);
        if (issued <= completed_before ||
            (epoch_enabled && completed_after != completed_before))
            shmem_global_exit(1);
        shmem_ctx_quiet(ctx);
        shmemx_pcntr_get_completed_write(ctx, &completed_after);
        if (completed_after != issued)
            shmem_global_exit(1);
        memset(source, 0xee, WRITES * BYTES);
        shmem_ctx_quiet(ctx); /* Empty epoch. */
    }
    shmem_barrier_all();
    if (me != 0)
        for (int i = 0; i < WRITES; i++)
            check(target + i * BYTES, i + 1);

    /* Blocking direct puts release the source at transmit completion while
     * remote-completion statistics stay pending until quiet.  No bounce
     * pool exists on this context, including with a larger bounce threshold. */
    if (me == 0) {
        uint64_t before, after, issued;
        shmemx_pcntr_get_completed_write(direct_ctx, &before);
        memset(source + (WRITES - 1) * BYTES, WRITES - 1 + 50, BYTES);
        for (int pe = 1; pe < npes; pe++)
            shmem_ctx_putmem_nbi(direct_ctx, target + (WRITES - 1) * BYTES,
                                source + (WRITES - 1) * BYTES, BYTES, pe);
        for (int i = 0; i < WRITES; i++) {
            memset(source, i + 50, BYTES);
            for (int pe = 1; pe < npes; pe++)
                shmem_ctx_putmem(direct_ctx, target + i * BYTES,
                                source, BYTES, pe);
            memset(source, 0xee, BYTES);
        }
        shmemx_pcntr_get_issued_write(direct_ctx, &issued);
        shmemx_pcntr_get_completed_write(direct_ctx, &after);
        if (issued <= before || (epoch_enabled && after != before))
            shmem_global_exit(1);
        shmem_ctx_quiet(direct_ctx);
        shmemx_pcntr_get_completed_write(direct_ctx, &after);
        if (after != issued)
            shmem_global_exit(1);
    }
    shmem_barrier_all();
    if (me != 0)
        for (int i = 0; i < WRITES; i++)
            check(target + i * BYTES, i + 50);

    /* Default-context blocking puts must also release their source. */
    if (me == 0) {
        memset(source, 42, BYTES);
        shmem_putmem(target, source, BYTES, 1);
        memset(source, 0xee, BYTES);
        shmem_quiet();
    }
    shmem_barrier_all();
    if (me == 1)
        check(target, 42);

    /* Quiet orders ordinary writes before subsequent epoch writes. */
    if (me == 0) {
        shmem_uchar_p(target, 0xee, 1);
        shmem_quiet();
        memset(source, 45, BYTES);
        shmem_putmem_nbi(target, source, BYTES, 1);
        shmem_quiet();
    }
    shmem_barrier_all();
    if (me == 1)
        check(target, 45);

    /* Use quiet for cross-endpoint ordering before a small notification. */
    if (me == 0) {
        memset(source, 43, BYTES);
        shmem_putmem_nbi(target, source, BYTES, 1);
        shmem_fence();
        shmem_quiet();
        shmem_long_p(ready, 1, 1);
        shmem_long_wait_until(reply, SHMEM_CMP_EQ, 1);
        shmem_quiet();
    } else if (me == 1) {
        shmem_long_wait_until(ready, SHMEM_CMP_EQ, 1);
        check(target, 43);
        shmem_long_p(reply, 1, 0);
        shmem_quiet();
    }
    shmem_barrier_all();

    /* Put-with-signal must order across the epoch and ordinary endpoints. */
    if (me == 0) {
        memset(source, 44, BYTES);
        shmem_putmem_signal_nbi(target, source, BYTES, signal, 1,
                               SHMEM_SIGNAL_SET, 1);
        shmem_quiet();
    } else if (me == 1) {
        shmem_signal_wait_until(signal, SHMEM_CMP_EQ, 1);
        check(target, 44);
    }
    shmem_barrier_all();

    /* Blocking put-with-signal uses a separate binding from its NBI form.
     * The receiver checks before any barrier can hide an early signal. */
    if (me == 0) {
        memset(source, 46, BYTES);
        shmem_putmem_signal(target, source, BYTES, signal, 2,
                           SHMEM_SIGNAL_SET, 1);
        memset(source, 0xee, BYTES);
        shmem_quiet();
    } else if (me == 1) {
        shmem_signal_wait_until(signal, SHMEM_CMP_EQ, 2);
        check(target, 46);
    }
    shmem_barrier_all();

    /* Collective notifications must still follow remote payload completion,
     * although public blocking puts and public fence no longer quiet epochs. */
    memset(target + BYTES, me == 0 ? 77 : 0, BYTES);
    shmem_barrier_all();
    if (shmem_broadcastmem(SHMEM_TEAM_WORLD, target, target + BYTES, BYTES, 0))
        shmem_global_exit(1);
    if (me != 0)
        check(target, 77);
    shmem_barrier_all();
    int *reduce_source = (int *) (target + BYTES);
    int *reduce_target = (int *) target;
    size_t elements = BYTES / sizeof(int);
    for (size_t i = 0; i < elements; i++)
        reduce_source[i] = me + 1;
    shmem_barrier_all();
    if (shmem_int_sum_reduce(SHMEM_TEAM_WORLD, reduce_target,
                             reduce_source, elements))
        shmem_global_exit(1);
    for (size_t i = 0; i < elements; i++)
        if (reduce_target[i] != npes * (npes + 1) / 2)
            shmem_global_exit(1);
    shmem_barrier_all();
    shmem_ctx_destroy(direct_ctx);
    shmem_ctx_destroy(ctx);
    free(source);
    shmem_free(signal);
    shmem_free(reply);
    shmem_free(ready);
    shmem_free(target);
    shmem_finalize();
    return 0;
}
