/*
 * Synchronization-only OFI bounce-buffer payload regression.
 * Intended for two PEs on different nodes, with injection size < BLOCK_BYTES,
 * SHMEM_BOUNCE_SIZE=4096 and SHMEM_MAX_BOUNCE_BUFFERS=2.
 * Default: SHMEM_OFI_BOUNCE_QUEUE=1. With --immediate, use queue=0.
 * Static analysis only in this workspace; this test has not been run.
 */
#include <shmem.h>
#include <shmemx.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_BYTES 1024
#define BLOCKS 17

static void
send_blocks(shmem_ctx_t ctx, unsigned char *target)
{
    unsigned char source[BLOCK_BYTES];
    int block;

    /* Descending addresses require separate writes and overflow a small pool. */
    for (block = BLOCKS - 1; block >= 0; --block) {
        memset(source, block + 1, sizeof(source));
        shmem_ctx_putmem(ctx, target + block * BLOCK_BYTES, source,
                         sizeof(source), 1);
        memset(source, 0xee, sizeof(source));
    }
}

static void
check_blocks(const unsigned char *target)
{
    int block;
    size_t byte;

    for (block = 0; block < BLOCKS; ++block) {
        for (byte = 0; byte < BLOCK_BYTES; ++byte) {
            if (target[block * BLOCK_BYTES + byte] != block + 1) {
                fprintf(stderr, "PE %d: block %d byte %zu mismatch\n",
                        shmem_my_pe(), block, byte);
                shmem_global_exit(1);
            }
        }
    }
}

int
main(int argc, char **argv)
{
    unsigned char *target;
    long *ready;
    shmem_ctx_t ctx;
    int me, phase;
    int expect_queue = !(argc == 2 && strcmp(argv[1], "--immediate") == 0);

    shmem_init();
    me = shmem_my_pe();
    if (shmem_n_pes() != 2)
        shmem_global_exit(1);
    target = shmem_malloc(BLOCKS * BLOCK_BYTES);
    ready = shmem_malloc(sizeof(*ready));
    if (!target || !ready)
        shmem_global_exit(1);

    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (shmem_ctx_create(SHMEM_CTX_PRIVATE | SHMEMX_CTX_BOUNCE_BUFFER, &ctx))
        shmem_global_exit(1);
    if (me == 0) {
        uint64_t before, issued, completed, issued_after;
        shmemx_pcntr_get_completed_write(ctx, &before);
        send_blocks(ctx, target);
        shmemx_pcntr_get_issued_write(ctx, &issued);
        shmemx_pcntr_get_completed_write(ctx, &completed);
        /* An immediate-send implementation with the specified two-buffer
         * pool must reclaim completions to accept all 17 copied puts. */
        if ((expect_queue && completed != before) ||
            (!expect_queue && completed <= before) || issued <= before)
            shmem_global_exit(1);
        shmem_ctx_quiet(ctx);
        shmemx_pcntr_get_issued_write(ctx, &issued_after);
        shmemx_pcntr_get_completed_write(ctx, &completed);
        if (issued_after != issued || completed != issued)
            shmem_global_exit(1);
    }
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target);
    shmem_ctx_destroy(ctx);

    for (phase = 0; phase < 4; ++phase) {
        memset(target, 0, BLOCKS * BLOCK_BYTES);
        *ready = 0;
        shmem_barrier_all();
        if (me == 0) {
            send_blocks(SHMEM_CTX_DEFAULT, target);
            if (phase == 0)
                shmem_quiet();
            else if (phase == 1)
                shmem_fence();
            else if (phase == 2)
                shmem_barrier_all();
            else {
                /* A direct NBI put shares the eventual quiet boundary. */
                unsigned char source[BLOCK_BYTES];
                memset(source, 1, sizeof(source));
                shmem_putmem_nbi(target, source, sizeof(source), 1);
                shmem_quiet();
            }
            shmem_long_p(ready, 1, 1);
            shmem_quiet();
        } else {
            if (phase == 2)
                shmem_barrier_all();
            shmem_long_wait_until(ready, SHMEM_CMP_EQ, 1);
            check_blocks(target);
        }
        shmem_barrier_all();
    }

    /* Destruction completes a created context's queued output. */
    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (shmem_ctx_create(SHMEM_CTX_PRIVATE | SHMEMX_CTX_BOUNCE_BUFFER, &ctx))
        shmem_global_exit(1);
    if (me == 0)
        send_blocks(ctx, target);
    shmem_ctx_destroy(ctx);
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target);

    /* A single blocking put larger than the bounce segment size must finish
     * using its source while retaining all copied segments until quiet. */
    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (me == 0) {
        unsigned char *source = malloc(BLOCKS * BLOCK_BYTES);
        int block;
        if (!source)
            shmem_global_exit(1);
        for (block = 0; block < BLOCKS; ++block)
            memset(source + block * BLOCK_BYTES, block + 1, BLOCK_BYTES);
        shmem_putmem(target, source, BLOCKS * BLOCK_BYTES, 1);
        memset(source, 0xee, BLOCKS * BLOCK_BYTES);
        free(source);
        shmem_quiet();
    }
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target);

    shmem_free(ready);
    shmem_free(target);
    if (me == 0)
        printf("OFI bounce payload checks completed (%s mode)\n",
               expect_queue ? "queued" : "immediate");
    shmem_finalize();
    return 0;
}
