/*
 * Public-API regression for optional OFI bounce-buffer batching.
 * See ofi_bounce_batch.md for the configuration matrix.
 * This source is intentionally independent of the tests-sos submodule.
 */
#include <shmem.h>
#include <shmemx.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_BYTES 1024
#define BLOCKS 17

static void
check_blocks(const unsigned char *target, int blocks)
{
    int block;
    size_t byte;

    for (block = 0; block < blocks; block++) {
        for (byte = 0; byte < BLOCK_BYTES; byte++) {
            if (target[block * BLOCK_BYTES + byte] != (unsigned char) (block + 1)) {
                fprintf(stderr, "PE %d: incorrect block %d, byte %zu\n",
                        shmem_my_pe(), block, byte);
                shmem_global_exit(1);
            }
        }
    }
}

static void
send_blocks(shmem_ctx_t ctx, unsigned char *target, int blocks, int peer)
{
    unsigned char source[BLOCK_BYTES];
    int block;

    for (block = 0; block < blocks; block++) {
        memset(source, block + 1, sizeof(source));
        shmem_ctx_putmem(ctx, target + block * BLOCK_BYTES, source,
                         sizeof(source), peer);
        /* A blocking put must have completed use of this source. */
        memset(source, 0xee, sizeof(source));
    }
}

int
main(int argc, char **argv)
{
    unsigned char *target;
    long *ready, *reply;
    shmem_ctx_t ctx;
    int me;

    if (argc == 2 && strcmp(argv[1], "--multiple") == 0) {
        int provided;
        shmem_init_thread(SHMEM_THREAD_MULTIPLE, &provided);
        if (provided != SHMEM_THREAD_MULTIPLE)
            shmem_global_exit(1);
    } else {
        shmem_init();
    }
    me = shmem_my_pe();
    if (shmem_n_pes() != 2) {
        if (me == 0)
            fprintf(stderr, "ofi_bounce_batch requires exactly two PEs\n");
        shmem_global_exit(1);
    }

    target = shmem_malloc(BLOCKS * BLOCK_BYTES);
    ready = shmem_malloc(sizeof(*ready));
    reply = shmem_malloc(sizeof(*reply));
    if (target == NULL || ready == NULL || reply == NULL)
        shmem_global_exit(1);
    memset(target, 0, BLOCKS * BLOCK_BYTES);
    *ready = *reply = 0;
    shmem_barrier_all();

    /* More source segments than the small-pool configurations can retain. */
    if (me == 0) {
        send_blocks(SHMEM_CTX_DEFAULT, target, BLOCKS, 1);
        shmem_quiet();
    }
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target, BLOCKS);

    /* Descending targets cannot coalesce, even with a large bounce buffer.
     * A small pool must make progress rather than waiting on unposted work. */
    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (me == 0) {
        unsigned char source[BLOCK_BYTES];
        int block;
        for (block = BLOCKS - 1; block >= 0; block--) {
            memset(source, block + 1, sizeof(source));
            shmem_putmem(target + block * BLOCK_BYTES, source, sizeof(source), 1);
            memset(source, 0xee, sizeof(source));
        }
        shmem_quiet();
    }
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target, BLOCKS);

    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (me == 0) {
        send_blocks(SHMEM_CTX_DEFAULT, target, 2, 1);
        shmem_fence();
        shmem_long_p(ready, 1, 1);
        shmem_long_wait_until(reply, SHMEM_CMP_EQ, 1);
    } else {
        shmem_long_wait_until(ready, SHMEM_CMP_EQ, 1);
        check_blocks(target, 2);
        shmem_long_p(reply, 1, 0);
        shmem_quiet();
    }
    shmem_barrier_all();

    memset(target, 0, BLOCKS * BLOCK_BYTES);
    *ready = *reply = 0;
    shmem_barrier_all();
    if (shmem_ctx_create(SHMEM_CTX_PRIVATE | SHMEMX_CTX_BOUNCE_BUFFER, &ctx))
        shmem_global_exit(1);

    /* PE 0 queues below threshold on a created context, then waits on the
     * default context. Progress must submit the created context's queue. */
    if (me == 0) {
        send_blocks(ctx, target, 1, 1);
        shmem_long_wait_until(reply, SHMEM_CMP_EQ, 1);
    } else {
        shmem_uint32_wait_until((uint32_t *) target, SHMEM_CMP_EQ,
                                UINT32_C(0x01010101));
        /* First-word visibility alone is not a payload completion check.
         * The sender's later quiet/barrier establishes the check boundary. */
        shmem_long_p(reply, 1, 0);
        shmem_quiet();
    }
    shmem_ctx_quiet(ctx);
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target, 1);

    /* The test API must also advance a request queued on another context. */
    memset(target, 0, BLOCKS * BLOCK_BYTES);
    *reply = 0;
    shmem_barrier_all();
    if (me == 0) {
        send_blocks(ctx, target, 1, 1);
        while (!shmem_long_test(reply, SHMEM_CMP_EQ, 1))
            ;
    } else {
        shmem_uint32_wait_until((uint32_t *) target, SHMEM_CMP_EQ,
                                UINT32_C(0x01010101));
        shmem_long_p(reply, 1, 0);
        shmem_quiet();
    }
    shmem_ctx_quiet(ctx);
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target, 1);

    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (me == 0) {
        unsigned char source[BLOCK_BYTES];
        send_blocks(ctx, target, 1, 1);
        memset(source, 2, sizeof(source));
        shmem_ctx_putmem_nbi(ctx, target + BLOCK_BYTES, source, sizeof(source), 1);
        shmem_ctx_quiet(ctx);
    }
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target, 2);

    memset(target, 0, BLOCKS * BLOCK_BYTES);
    shmem_barrier_all();
    if (me == 0)
        send_blocks(ctx, target, 1, 1);
    /* Destruction must resolve copied-buffer ownership before freeing it. */
    shmem_ctx_destroy(ctx);
    shmem_barrier_all();
    if (me == 1)
        check_blocks(target, 1);

    shmem_free(reply);
    shmem_free(ready);
    shmem_free(target);
    if (me == 0)
        puts("OFI bounce batching payload checks completed");
    shmem_finalize();
    return 0;
}
