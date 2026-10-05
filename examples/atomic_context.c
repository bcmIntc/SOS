/* -*- C -*- */

#include <shmem.h>
#include <stdio.h>
#include <unistd.h>

static long target;
static unsigned long bits;

int main(void)
{
    shmem_init();
    int me = shmem_my_pe();
    int npes = shmem_n_pes();
    int peer = (me + npes / 2) % npes;
    int errors = 0;
    shmem_ctx_t first, second;
    char host[256];

    if (gethostname(host, sizeof(host)) != 0)
        shmem_global_exit(1);
    host[sizeof(host) - 1] = '\0';
    printf("atomic_context PE %d/%d on %s\n", me, npes, host);
    fflush(stdout);

    if (npes < 2) {
        if (me == 0)
            fprintf(stderr, "atomic_context requires at least two PEs\n");
        shmem_finalize();
        return 1;
    }
    if (shmem_ctx_create(0, &first) || shmem_ctx_create(0, &second)) {
        fprintf(stderr, "PE %d: could not create two contexts\n", me);
        shmem_global_exit(1);
    }

    target = 0;
    shmem_barrier_all();
    shmem_long_p(&target, 10, peer);
    shmem_long_atomic_add(&target, 1, peer);
    shmem_quiet();
    shmem_barrier_all();
    if (target != 11) {
        fprintf(stderr, "PE %d: put then add gave %ld, expected 11\n", me, target);
        ++errors;
    }

    target = 0;
    shmem_barrier_all();
    shmem_long_atomic_add(&target, 1, peer);
    shmem_long_p(&target, 13, peer);
    shmem_quiet();
    shmem_barrier_all();
    if (target != 13) {
        fprintf(stderr, "PE %d: add then put gave %ld, expected 13\n", me, target);
        ++errors;
    }

    target = 0;
    shmem_barrier_all();
    shmem_ctx_long_p(first, &target, 17, peer);
    shmem_ctx_long_atomic_add(first, &target, 1, peer);
    shmem_ctx_quiet(first);
    shmem_barrier_all();
    if (target != 18) {
        fprintf(stderr, "PE %d: context put then add gave %ld, expected 18\n", me, target);
        ++errors;
    }

    target = 0;
    shmem_barrier_all();
    shmem_ctx_long_atomic_add(first, &target, 1, peer);
    shmem_ctx_long_p(first, &target, 19, peer);
    shmem_ctx_quiet(first);
    shmem_barrier_all();
    if (target != 19) {
        fprintf(stderr, "PE %d: context add then put gave %ld, expected 19\n", me, target);
        ++errors;
    }

    target = 0;
    bits = 7;
    shmem_barrier_all();
    long old = shmem_ctx_long_atomic_compare_swap(first, &target, 0, 5, peer);
    long fetched = shmem_ctx_long_atomic_fetch(first, &target, peer);
    long swapped = shmem_ctx_long_atomic_swap(first, &target, 7, peer);
    unsigned long bitwise = shmem_ctx_ulong_atomic_fetch_xor(first, &bits, 3, peer);
    shmem_ctx_fence(first);
    shmem_ctx_long_p(first, &target, 11, peer);
    shmem_ctx_quiet(first);
    shmem_barrier_all();
    if (old != 0 || fetched != 5 || swapped != 5 || bitwise != 7 ||
        bits != 4 || target != 11) {
        fprintf(stderr, "PE %d: fetch/swap/bitwise/fence gave %ld/%ld/%ld/%lu/%lu/%ld\n",
                me, old, fetched, swapped, bitwise, bits, target);
        ++errors;
    }

    target = 0;
    shmem_barrier_all();
    long result[3] = {-1, -1, -1};
    shmem_ctx_long_atomic_fetch_add_nbi(first, &result[0], &target, 1, peer);
    shmem_ctx_long_atomic_fetch_add_nbi(second, &result[1], &target, 1, peer);
    shmem_long_atomic_fetch_add_nbi(&result[2], &target, 1, peer);
    shmem_ctx_quiet(first);
    shmem_ctx_quiet(second);
    shmem_quiet();
    shmem_barrier_all();
    if (target != 3 || result[0] < 0 || result[1] < 0 || result[2] < 0 ||
        result[0] + result[1] + result[2] != 3) {
        fprintf(stderr, "PE %d: NBI target %ld, results %ld/%ld/%ld (expected 3, permutation of 0/1/2)\n",
                me, target, result[0], result[1], result[2]);
        ++errors;
    }

    shmem_ctx_destroy(first);
    shmem_ctx_destroy(second);
    if (errors)
        fprintf(stderr, "PE %d: %d atomic context checks failed\n", me, errors);
    shmem_finalize();
    return errors != 0;
}
