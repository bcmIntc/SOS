/* Public-API payload/source-reuse check for batches spanning destinations.
 * Requires >=3 PEs on distinct hosts. Barriers check eventual contents;
 * use the existing TCP quiet oracle separately for quiet-at-return delivery.
 */
#define _POSIX_C_SOURCE 200809L
#include <shmem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS 97
#define HOST_BYTES 256
static unsigned char pattern(int phase, int slot, size_t byte)
{
    return (unsigned char)(1 + (phase * 31 + slot * 7 + byte % 251) % 253);
}

int main(int argc, char **argv)
{
    const char *requested = getenv("SHMEM_OFI_PUT_MORE_BATCH");
    char *batch_end;
    unsigned long batch = requested ? strtoul(requested, &batch_end, 10) : 0;
    if (!requested || !*requested || *batch_end || batch < 2 || batch > 16) {
        fprintf(stderr, "SKIP: set SHMEM_OFI_PUT_MORE_BATCH to 2-16; use run-ofi-more.sh for evidence checks\n");
        return 77;
    }
    size_t bytes = 1024;
    if (argc == 2) {
        char *end;
        unsigned long n = strtoul(argv[1], &end, 10);
        if (!*argv[1] || *end || n < 1 || n > 8192) return 1;
        bytes = n;
    } else if (argc != 1) return 1;
    int provided;
    shmem_init_thread(SHMEM_THREAD_SINGLE, &provided);
    int me = shmem_my_pe(), npes = shmem_n_pes();
    if (provided != SHMEM_THREAD_SINGLE || npes < 3) {
        shmem_finalize();
        return 77;
    }
    char *host = shmem_malloc(HOST_BYTES);
    unsigned char *target = shmem_malloc(SLOTS * bytes);
    long *word = shmem_malloc(sizeof(*word));
    unsigned char *source = malloc(bytes);
    if (!host || !target || !word || !source) shmem_global_exit(1);
    memset(host, 0, HOST_BYTES);
    if (gethostname(host, HOST_BYTES - 1)) shmem_global_exit(1);
    *word = 0;
    shmem_barrier_all();
    for (int pe = 0; pe < npes; pe++) {
        char peer_host[HOST_BYTES];
        shmem_getmem(peer_host, host, HOST_BYTES, pe);
        if (pe != me && !strcmp(host, peer_host)) {
            if (!me) fprintf(stderr, "SKIP: ofi_more needs one PE per distinct host\n");
            shmem_global_exit(77);
        }
    }
    const int counts[] = {3, 32, SLOTS, 31};
    for (int phase = 0; phase < 4; phase++) {
        memset(target, 0, SLOTS * bytes);
        shmem_barrier_all();
        if (!me) {
            for (int slot = 0; slot < counts[phase]; slot++) {
                int pe = 1 + slot % (npes - 1);
                for (size_t b = 0; b < bytes; b++)
                    source[b] = pattern(phase, slot, b);
                shmem_putmem(target + slot * bytes, source, bytes, pe);
                memset(source, 0xee, bytes);
                if (phase == 3 && slot % 3 == 2) {
                    long observed;
                    shmem_getmem(&observed, word, sizeof(observed), pe);
                    if (observed != 0) shmem_global_exit(1);
                }
            }
            shmem_quiet();
        }
        shmem_barrier_all();
        if (me)
            for (int slot = 0; slot < counts[phase]; slot++)
                if (1 + slot % (npes - 1) == me)
                    for (size_t b = 0; b < bytes; b++)
                        if (target[slot * bytes + b] != pattern(phase, slot, b))
                            shmem_global_exit(1);
    }
    shmem_barrier_all();
    if (!me) fprintf(stderr, "OFI MORE cleanup: freeing allocations\n");
    free(source);
    shmem_free(word);
    shmem_free(target);
    shmem_free(host);
    if (!me) fprintf(stderr, "OFI MORE cleanup: finalizing\n");
    shmem_finalize();
    if (!me) printf("OFI MORE payload check passed: bytes=%zu phases=4 PEs=%d\n",
                    bytes, npes);
    return 0;
}
