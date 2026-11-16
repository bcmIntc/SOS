/* Cross-node payload/source-reuse regression with uniform and uneven local
 * senders. Run >=2 nodes and >=2 PEs/node; every put crosses a host boundary. */
#define _POSIX_C_SOURCE 200809L
#include <shmem.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define HOST_BYTES 256
#define SLOTS 257

static unsigned char pattern(int phase, int pe, int slot, size_t byte)
{
    return (unsigned char)(1 + (phase * 31 + pe * 13 + slot * 7 + byte % 251) % 253);
}
static int active(int phase, int rank)
{
    return phase == 0 || phase == 2 || rank == phase / 2;
}
int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s BYTES LOCAL_PES (BYTES=1-8192, LOCAL_PES>=2)\n", argv[0]);
        return 2;
    }
    char *end;
    unsigned long bytes = strtoul(argv[1], &end, 10);
    if (!*argv[1] || *end || bytes < 1 || bytes > 8192) return 2;
    unsigned long expected = strtoul(argv[2], &end, 10);
    if (!*argv[2] || *end || expected < 2 || expected > 1048576) return 2;
    int provided;
    shmem_init_thread(SHMEM_THREAD_SINGLE, &provided);
    int me = shmem_my_pe(), npes = shmem_n_pes();
    if (provided != SHMEM_THREAD_SINGLE || (size_t)npes > SIZE_MAX / SLOTS / bytes)
        shmem_global_exit(1);
    char *host = shmem_malloc(HOST_BYTES);
    size_t total = (size_t)npes * SLOTS * bytes;
    unsigned char *target = shmem_malloc(total), *source = malloc(bytes);
    char (*hosts)[HOST_BYTES] = calloc((size_t)npes, HOST_BYTES);
    int *ranks = calloc((size_t)npes, sizeof(*ranks));
    int *dest = malloc((size_t)npes * sizeof(*dest));
    if (!host || !target || !source || !hosts || !ranks || !dest) shmem_global_exit(1);
    memset(host, 0, HOST_BYTES);
    if (gethostname(host, HOST_BYTES - 1)) shmem_global_exit(1);
    shmem_barrier_all();
    for (int pe = 0; pe < npes; pe++)
        shmem_getmem(hosts[pe], host, HOST_BYTES, pe);
    for (int pe = 0; pe < npes; pe++) {
        int local = 0;
        dest[pe] = -1;
        for (int other = 0; other < npes; other++) {
            if (!strcmp(hosts[pe], hosts[other])) {
                local++;
                if (other < pe) ranks[pe]++;
            }
        }
        for (int i = 1; i < npes; i++) {
            int other = (pe + i) % npes;
            if (strcmp(hosts[pe], hosts[other])) { dest[pe] = other; break; }
        }
        if (local != (int)expected || dest[pe] < 0) {
            if (!me) fprintf(stderr, "FAIL: need >=2 distinct hosts with %lu PEs each\n", expected);
            shmem_global_exit(1);
        }
    }
    for (int phase = 0; phase < 4; phase++) {
        memset(target, 0, total);
        shmem_barrier_all();
        if (active(phase, ranks[me])) {
            for (int slot = 0; slot < SLOTS; slot++) {
                for (size_t b = 0; b < bytes; b++)
                    source[b] = pattern(phase, me, slot, b);
                shmem_putmem(target + ((size_t)me * SLOTS + slot) * bytes,
                             source, bytes, dest[me]);
                memset(source, 0xee, bytes); /* Blocking-put source is reusable. */
            }
            shmem_quiet();
        }
        shmem_barrier_all();
        for (int pe = 0; pe < npes; pe++)
            if (dest[pe] == me && active(phase, ranks[pe]))
                for (int slot = 0; slot < SLOTS; slot++)
                    for (size_t b = 0; b < bytes; b++)
                        if (target[((size_t)pe * SLOTS + slot) * bytes + b] !=
                            pattern(phase, pe, slot, b)) {
                            fprintf(stderr, "FAIL: receiver=%d sender=%d phase=%d slot=%d byte=%zu\n",
                                    me, pe, phase, slot, b);
                            shmem_global_exit(1);
                        }
    }
    shmem_barrier_all();
    free(dest); free(ranks); free(hosts); free(source);
    shmem_free(target); shmem_free(host);
    shmem_finalize();
    if (!me) printf("OFI node budget payload check passed: bytes=%lu phases=4 PEs=%d local_pes=%lu\n",
                    bytes, npes, expected);
    return 0;
}
