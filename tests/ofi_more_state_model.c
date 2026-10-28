/* Exercises the production submission state, not a separate batching model.
 * Explicit local target: no MPI/libsma linkage. Run after building on the host.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#define FI_MORE UINT64_C(1)
#include "transport_ofi_more_state.h"

int main(void)
{
    shmem_transport_ofi_more_state_t s = {.limit = 4, .stats = true};
    for (unsigned int i = 0; i < 4; i++) {
        uint64_t flags = shmem_transport_ofi_more_flags(&s, true);
        assert(!!(flags & FI_MORE) == (i < 3));
        shmem_transport_ofi_more_accept(&s, true, flags, OFI_MORE_FULL);
    }
    assert(s.count == 0 && s.puts == 4 && s.more == 3);
    assert(s.batches == 1 && s.full == 1 && s.batched_puts == 4);
    assert(s.tx_posts == 4);

    /* Destination selection is independent of batching state: callers may
     * change the target on every write on the same exclusive TX queue. */
    shmem_transport_ofi_more_accept(&s, true, FI_MORE, OFI_MORE_FULL);
    shmem_transport_ofi_more_accept(&s, true, FI_MORE, OFI_MORE_FULL);
    shmem_transport_ofi_more_accept(&s, false, 0, OFI_MORE_OTHER);
    assert(s.count == 0 && s.other == 1 && s.batched_puts == 6);
    assert(s.tx_posts == 7);

    shmem_transport_ofi_more_accept(&s, true, FI_MORE, OFI_MORE_FULL);
    shmem_transport_ofi_more_accept(&s, false, 0, OFI_MORE_QUIET);
    assert(s.flushes == 1 && s.ends[OFI_MORE_QUIET] == 1);
    assert(s.batched_puts == s.puts && s.count == 0);
    assert(shmem_transport_ofi_more_flags(&s, false) == 0);

    for (int reason = OFI_MORE_QUIET; reason < OFI_MORE_REASONS; reason++) {
        shmem_transport_ofi_more_accept(&s, true, FI_MORE, OFI_MORE_FULL);
        shmem_transport_ofi_more_accept(&s, false, 0, reason);
        assert(s.ends[reason] > 0 && s.count == 0);
    }
    assert(s.batched_puts == s.puts);

    s = (shmem_transport_ofi_more_state_t){.stats = true};
    assert(shmem_transport_ofi_more_flags(&s, true) == 0);
    shmem_transport_ofi_more_accept(&s, true, 0, OFI_MORE_FULL);
    assert(s.more == 0 && s.tx_posts == 0 && s.puts == 1);

    s = (shmem_transport_ofi_more_state_t){.limit = 1, .stats = true};
    assert(shmem_transport_ofi_more_flags(&s, true) == 0);
    shmem_transport_ofi_more_accept(&s, true, 0, OFI_MORE_FULL);
    assert(s.count == 0 && s.more == 0 && s.full == 1);
    return 0;
}
