/* Standalone coverage of the production quota helper; no OFI/MPI dependency. */
#define _GNU_SOURCE
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "transport_ofi_node_budget.h"

static void quotas(void)
{
    uint64_t available = 20;
    shmem_transport_ofi_node_quota_t q = {0};
    assert(shmem_transport_ofi_node_admit(&q, 1000));
    shmem_transport_ofi_node_release(&q, 0);
    assert(available == 20);
    assert(shmem_transport_ofi_node_valid(2, 16, 64, 32));
    assert(!shmem_transport_ofi_node_valid(2, 0, 64, 32));
    assert(!shmem_transport_ofi_node_valid(2, 16, 64, 31));
    assert(!shmem_transport_ofi_node_valid(2, 16, 64, 129));
    assert(!shmem_transport_ofi_node_valid(SIZE_MAX, 16, 64, 32));
    shmem_transport_ofi_node_attach(&q, &available, 8, 32);
    assert(shmem_transport_ofi_node_admit(&q, 7));
    assert(available == 20);
    assert(shmem_transport_ofi_node_admit(&q, 8));
    assert(q.capacity == 16 && available == 12);
    assert(shmem_transport_ofi_node_admit(&q, 16));
    assert(shmem_transport_ofi_node_admit(&q, 24));
    assert(q.capacity == 28 && available == 0); /* Partial loan. */
    assert(!shmem_transport_ofi_node_admit(&q, 28));
    shmem_transport_ofi_node_quota_t peer;
    shmem_transport_ofi_node_attach(&peer, &available, 8, 32);
    /* q stays idle holding every shared slot; peer can repeatedly complete
     * and reuse its private guarantee without requiring q to return a loan. */
    for (int i = 0; i < 100; i++) {
        for (size_t used = 0; used < 8; used++)
            assert(shmem_transport_ofi_node_admit(&peer, used));
        assert(!shmem_transport_ofi_node_admit(&peer, 8));
        shmem_transport_ofi_node_release(&peer, 0);
        assert(q.capacity == 28 && available == 0 && peer.capacity == 8);
    }
    shmem_transport_ofi_node_release(&q, 27);
    assert(q.capacity == 28 && available == 0); /* Owned slots retained. */
    shmem_transport_ofi_node_release(&q, 18);
    assert(q.capacity == 20 && available == 8);
    shmem_transport_ofi_node_release(&q, 0);
    assert(q.capacity == 8 && available == 20);
    assert(q.borrowed == q.returned);
    available = 0; /* Another PE may retain every shared slot indefinitely. */
    assert(shmem_transport_ofi_node_admit(&q, 0));
    assert(shmem_transport_ofi_node_admit(&q, 7));
    assert(!shmem_transport_ofi_node_admit(&q, 8));
    available = 100;
    assert(shmem_transport_ofi_node_admit(&q, 8));
    assert(shmem_transport_ofi_node_admit(&q, 16));
    assert(shmem_transport_ofi_node_admit(&q, 24));
    assert(q.capacity == 32);
    assert(!shmem_transport_ofi_node_admit(&q, 32)); /* Physical limit. */
    shmem_transport_ofi_node_release(&q, 0);
    assert(available == 100);
}

static void processes(void)
{
    uint64_t *available = mmap(NULL, sizeof(*available), PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    assert(available != MAP_FAILED);
    *available = 192; /* Eight private guarantees of eight; total budget 256. */
    for (int i = 0; i < 8; i++) {
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) {
            shmem_transport_ofi_node_quota_t q;
            shmem_transport_ofi_node_attach(&q, available, 8, 64);
            for (int j = 0; j < 10000; j++) {
                for (size_t used = 8; used < 64; used += 8) {
                    if (!shmem_transport_ofi_node_admit(&q, used)) break;
                    assert(q.capacity <= 64);
                    assert(__atomic_load_n(available, __ATOMIC_ACQUIRE) <= 192);
                }
                shmem_transport_ofi_node_release(&q, 0);
                assert(q.capacity == 8 && q.borrowed == q.returned);
            }
            _exit(0);
        }
    }
    for (int i = 0; i < 8; i++) {
        int status;
        assert(wait(&status) > 0);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    assert(*available == 192);
    assert(munmap(available, sizeof(*available)) == 0);
}

int main(void)
{
    assert(__atomic_always_lock_free(sizeof(uint64_t), 0));
    quotas();
    processes();
    return 0;
}
