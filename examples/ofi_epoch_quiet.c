/* Regression for missing destination fences or premature quiet completion.
 * Run with at least two PEs and a sufficiently large symmetric heap.
 * Use sync_all after quiet: a barrier would itself complete outstanding puts
 * and could hide a broken quiet implementation.
 */
#include <shmem.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { payload_size = 65536, buffered_size = 256, burst_count = 512, epochs = 4 };

int main(void)
{
    shmem_init();
    int me = shmem_my_pe();
    int npes = shmem_n_pes();
    if (npes < 2) {
        if (me == 0) fputs("Run with at least two PEs\n", stderr);
        shmem_finalize();
        return 77;
    }
    unsigned char *target = shmem_malloc((size_t) npes * payload_size);
    unsigned char *buffered = shmem_malloc((size_t) npes * buffered_size);
    long *counts = shmem_malloc((size_t) npes * sizeof(*counts));
    uint64_t *signals = shmem_malloc((size_t) npes * sizeof(*signals));
    unsigned char *scalars = shmem_malloc((size_t) npes);
    unsigned char *source = malloc(payload_size);
    shmem_ctx_t ctx;

    if (!target || !buffered || !counts || !signals || !scalars || !source ||
        shmem_ctx_create(0, &ctx) != 0)
        shmem_global_exit(1);
    memset(counts, 0, (size_t) npes * sizeof(*counts));
    memset(signals, 0, (size_t) npes * sizeof(*signals));
    shmem_barrier_all();

    for (int context = 0; context < 2; context++) {
        shmem_ctx_t active = context ? ctx : SHMEM_CTX_DEFAULT;
        for (int epoch = 0; epoch < epochs; epoch++) {
            unsigned char value = (unsigned char) (me + epoch + 1);
            memset(source, value, payload_size);
            for (int pe = 0; pe < npes; pe++) {
                shmem_ctx_putmem(active, buffered + (size_t) me * buffered_size,
                                 source, buffered_size, pe);
                shmem_ctx_putmem_nbi(active, target + (size_t) me * payload_size,
                                     source, payload_size, pe);
                shmem_ctx_long_atomic_add(active, &counts[me], 1, pe);
                /* Exercise retry progress with many unsignaled writes. */
                for (int put = 0; put < burst_count; put++)
                    shmem_ctx_uchar_p(active, &scalars[me], value, pe);
            }
            shmem_ctx_quiet(active);
            /* A completed epoch must permit immediate reuse of the source. */
            memset(source, 0xff, payload_size);
            shmem_ctx_quiet(active); /* Empty epoch. */
            shmem_sync_all();

            for (int sender = 0; sender < npes; sender++) {
                unsigned char expected = (unsigned char) (sender + epoch + 1);
                for (size_t i = 0; i < payload_size; i++)
                    if (target[(size_t) sender * payload_size + i] != expected)
                        shmem_global_exit(2);
                for (size_t i = 0; i < buffered_size; i++)
                    if (buffered[(size_t) sender * buffered_size + i] != expected)
                        shmem_global_exit(3);
                if (counts[sender] != context * epochs + epoch + 1)
                    shmem_global_exit(4);
                if (scalars[sender] != expected)
                    shmem_global_exit(5);
            }
            shmem_sync_all();

            /* Keep signals in a separate epoch: their ordering fence must
             * not complete the ordinary writes tested above. */
            memset(source, value ^ 0x80, payload_size);
            for (int pe = 0; pe < npes; pe++)
                shmem_ctx_putmem_signal_nbi(active,
                    buffered + (size_t) me * buffered_size, source, buffered_size,
                    &signals[me], context * epochs + epoch + 1, SHMEM_SIGNAL_SET, pe);
            shmem_ctx_quiet(active);
            memset(source, 0xff, payload_size);
            shmem_sync_all();
            for (int sender = 0; sender < npes; sender++) {
                unsigned char expected = (unsigned char) ((sender + epoch + 1) ^ 0x80);
                for (size_t i = 0; i < buffered_size; i++)
                    if (buffered[(size_t) sender * buffered_size + i] != expected)
                        shmem_global_exit(6);
                if (signals[sender] != (uint64_t) (context * epochs + epoch + 1))
                    shmem_global_exit(7);
            }
            shmem_sync_all(); /* Finish validation before the next epoch. */
        }
    }
    shmem_ctx_destroy(ctx);
    free(source);
    shmem_free(scalars);
    shmem_free(signals);
    shmem_free(counts);
    shmem_free(buffered);
    shmem_free(target);
    if (me == 0)
        puts("OFI epoch quiet regression passed");
    shmem_finalize();
    return 0;
}
