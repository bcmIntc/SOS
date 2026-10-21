/* Public-API regression for immediate CQ and counter-retired bounce puts.
 * An early internal source reuse must corrupt the overwrite/pool-pressure
 * cases; lost delivery or ordering must corrupt the receiver's byte checks.
 * Checks after barriers establish eventual contents, not quiet-at-return.
 */
#define _POSIX_C_SOURCE 200809L
#include <shmem.h>
#include <shmemx.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WRITES 17
#define EPOCHS 4
#define HOST_BYTES 256

static unsigned char
pattern(int epoch, int slot, size_t byte)
{
    return (unsigned char) (1 + (epoch * 31 + slot * 7 + byte % 251) % 253);
}

static void
check(const unsigned char *target, size_t bytes, int epoch)
{
    for (int slot = 0; slot < WRITES; slot++)
        for (size_t byte = 0; byte < bytes; byte++)
            if (target[(size_t) slot * bytes + byte] != pattern(epoch, slot, byte)) {
                fprintf(stderr, "PE %d: epoch=%d slot=%d byte=%zu mismatch\n",
                        shmem_my_pe(), epoch, slot, byte);
                shmem_global_exit(1);
            }
}

static void
send(shmem_ctx_t ctx, unsigned char *target, unsigned char *source,
     size_t bytes, int epoch)
{
    /* Alternate ascending and descending destinations; no payload merging. */
    for (int i = 0; i < WRITES; i++) {
        int slot = epoch % 2 ? WRITES - i - 1 : i;
        for (size_t byte = 0; byte < bytes; byte++)
            source[byte] = pattern(epoch, slot, byte);
        shmem_ctx_putmem(ctx, target + (size_t) slot * bytes, source, bytes, 1);
        memset(source, 0xee, bytes); /* Blocking return must release this source. */
    }
}

int
main(int argc, char **argv)
{
    size_t bytes = 1024;
    if (argc == 2) {
        char *end;
        unsigned long n = strtoul(argv[1], &end, 10);
        if (!*argv[1] || *end || n == 0 || n > 1024 * 1024)
            return 1;
        bytes = (size_t) n;
    } else if (argc != 1) {
        return 1;
    }
    int provided;
    shmem_init_thread(SHMEM_THREAD_SINGLE, &provided);
    if (provided != SHMEM_THREAD_SINGLE || shmem_n_pes() != 2) {
        shmem_finalize();
        return 77;
    }
    int me = shmem_my_pe();
    char *host = shmem_malloc(HOST_BYTES);
    unsigned char *target = shmem_malloc(EPOCHS * WRITES * bytes);
    unsigned char *source = malloc(bytes);
    unsigned char *nbi_source = malloc(WRITES * bytes);
    long *ready = shmem_malloc(sizeof(*ready));
    long *reply = shmem_malloc(sizeof(*reply));
    if (!host || !target || !source || !nbi_source || !ready || !reply)
        shmem_global_exit(1);
    memset(host, 0, HOST_BYTES);
    if (gethostname(host, HOST_BYTES - 1))
        shmem_global_exit(1);
    memset(target, 0, EPOCHS * WRITES * bytes);
    *ready = *reply = 0;
    shmem_barrier_all();
    char peer_host[HOST_BYTES];
    shmem_getmem(peer_host, host, HOST_BYTES, 1 - me);
    if (!strcmp(host, peer_host)) {
        if (me == 0)
            fprintf(stderr, "SKIP: OFI regression requires two different hosts\n");
        shmem_free(reply);
        shmem_free(ready);
        shmem_free(target);
        shmem_free(host);
        free(nbi_source);
        free(source);
        shmem_finalize();
        return 77;
    }

    for (int epoch = 0; epoch < EPOCHS; epoch++) {
        if (me == 0) {
            send(SHMEM_CTX_DEFAULT, target + epoch * WRITES * bytes,
                 source, bytes, epoch);
            /* Mix a non-fetching atomic with retained bounce sources. */
            shmem_long_atomic_inc(ready, 1);
            shmem_quiet();
            shmem_quiet(); /* Empty quiet must neither leak nor double-retire. */
        }
        shmem_barrier_all();
        if (me == 1)
            check(target + epoch * WRITES * bytes, bytes, epoch);
    }
    if (me == 1 && *ready != EPOCHS)
        shmem_global_exit(1);

    /* NBI uses a distinct source per slot, retained unchanged through quiet. */
    if (me == 0) {
        for (int slot = 0; slot < WRITES; slot++) {
            for (size_t byte = 0; byte < bytes; byte++)
                nbi_source[(size_t) slot * bytes + byte] = pattern(5, slot, byte);
            shmem_putmem_nbi(target + (size_t) slot * bytes,
                             nbi_source + (size_t) slot * bytes, bytes, 1);
        }
        shmem_quiet();
        memset(nbi_source, 0xee, WRITES * bytes);
    }
    shmem_barrier_all();
    if (me == 1)
        check(target, bytes, 5);

    *ready = *reply = 0;
    shmem_barrier_all();
    if (me == 0) {
        send(SHMEM_CTX_DEFAULT, target, source, bytes, 6);
        shmem_fence();
        shmem_long_p(ready, 1, 1);
        shmem_long_wait_until(reply, SHMEM_CMP_EQ, 1);
        shmem_quiet();
    } else {
        shmem_long_wait_until(ready, SHMEM_CMP_EQ, 1);
        check(target, bytes, 6);
        shmem_long_p(reply, 1, 0);
        shmem_quiet();
    }
    shmem_barrier_all();

    /* Created contexts keep CQ ownership even when default counter mode is on. */
    shmem_ctx_t ctx;
    if (shmem_ctx_create(SHMEM_CTX_PRIVATE | SHMEMX_CTX_BOUNCE_BUFFER, &ctx))
        shmem_global_exit(1);
    if (me == 0)
        send(ctx, target, source, bytes, 7);
    shmem_ctx_destroy(ctx);
    shmem_barrier_all();
    if (me == 1)
        check(target, bytes, 7);
    shmem_free(reply);
    shmem_free(ready);
    shmem_free(target);
    shmem_free(host);
    free(nbi_source);
    free(source);
    if (me == 0)
        puts("OFI immediate payload and source-lifetime checks completed");
    shmem_finalize();
    return 0;
}
