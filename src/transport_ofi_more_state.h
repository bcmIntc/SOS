/* Only accepted posts change submission state. Closing a submission batch
 * never reclaims a source: each payload retains its delivery CQ completion. */
#ifndef TRANSPORT_OFI_MORE_STATE_H
#define TRANSPORT_OFI_MORE_STATE_H
enum shmem_transport_ofi_more_reason {
    OFI_MORE_FULL, OFI_MORE_OTHER, OFI_MORE_QUIET, OFI_MORE_FENCE,
    OFI_MORE_POOL, OFI_MORE_CREDIT, OFI_MORE_RETRY, OFI_MORE_REBASE,
    OFI_MORE_GET_WAIT, OFI_MORE_PROBE, OFI_MORE_REASONS
};
typedef struct {
    size_t limit, count, budget;
    bool stats, locked, bounce_post;
    uint64_t bounce_flags, tx_posts;
    uint64_t puts, more, batches, batched_puts, full, other, flushes;
    uint64_t ends[OFI_MORE_REASONS], retries, admission_waits, dest_changes;
    uint64_t dest, addr, key;
} shmem_transport_ofi_more_state_t;
static inline uint64_t
shmem_transport_ofi_more_flags(const shmem_transport_ofi_more_state_t *s,
                              bool headroom)
{
    return headroom && s->limit > 1 && s->count + 1 < s->limit ? FI_MORE : 0;
}
static inline void
shmem_transport_ofi_more_accept(shmem_transport_ofi_more_state_t *s,
                               bool payload, uint64_t flags, int reason)
{
    if (s->limit) s->tx_posts++;
    if (payload && s->stats) s->puts++;
    if (flags & FI_MORE) {
        s->count++;
        if (s->stats) s->more++;
        return;
    }
    size_t payloads = s->count + (payload ? 1 : 0);
    if (payloads && s->stats) {
        s->batches++;
        s->batched_puts += payloads;
        if (payload && s->limit && payloads == s->limit) s->full++;
        else if (!payload && reason == OFI_MORE_OTHER) s->other++;
        if (!payload && reason >= OFI_MORE_QUIET) s->flushes++;
        s->ends[reason]++;
    }
    s->count = 0;
}
#endif
