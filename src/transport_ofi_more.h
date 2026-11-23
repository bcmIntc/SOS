/* Include after CQ progress and delivery-counter helpers. */
#ifndef TRANSPORT_OFI_MORE_H
#define TRANSPORT_OFI_MORE_H

/* Marker completion is never used to release payloads. A zero-byte delivery
 * write without FI_MORE rings the queue, and consumes one fabric-counter slot.
 * No new-source admission or wait includes an unaccepted retry member here. */
static inline void
shmem_transport_ofi_more_flush(shmem_transport_ctx_t *ctx, int reason)
{
    if (!ctx->put_more.count) return;
    shmem_internal_assert(ctx->put_cntr_pending < ctx->put_cntr_limit);
    const struct iovec iov = {
        .iov_base = shmem_internal_data_base, .iov_len = 0
    };
    const struct fi_rma_iov remote = {
        .addr = ctx->put_more.addr, .len = 0, .key = ctx->put_more.key
    };
    const struct fi_msg_rma msg = {
        .msg_iov = &iov,
        .desc = GET_MR_DESC_ADDR(shmem_transport_ofi_get_mr_desc_index(
                                    shmem_internal_data_base)),
        .iov_count = 1, .addr = ctx->put_more.dest,
        .rma_iov = &remote, .rma_iov_count = 1
    };
    ctx->put_cntr_pending++;
    for (unsigned int attempt = 0; attempt < 64; attempt++) {
        uint64_t cq_before = ctx->retry_probe_cq_events;
        int ret = fi_writemsg(ctx->ep, &msg, FI_DELIVERY_COMPLETE);
        if (!ret) {
            shmem_transport_ofi_more_accept(&ctx->put_more, false, 0, reason);
            return;
        }
        if (ret != -FI_EAGAIN) {
            shmem_transport_ofi_retry_probe(ctx, __func__, __LINE__, -1, 0,
                FI_DELIVERY_COMPLETE, ret, attempt + 1, cq_before, true);
            OFI_CTX_CHECK_ERROR(ctx, ret);
        }
        if (ctx->put_more.stats) ctx->put_more.retries++;
        if (ctx->bounce_buffers) SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx);
        shmem_transport_ofi_drain_cq(ctx);
        if (ctx->bounce_buffers) SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx);
        shmem_transport_probe();
        shmem_transport_ofi_retry_probe(ctx, __func__, __LINE__, -1, 0,
            FI_DELIVERY_COMPLETE, ret, attempt + 1, cq_before, attempt == 63);
    }
    /* TX/resource reservations are conservative, not a provider guarantee.
     * Fail with retained ownership rather than wait forever on unsubmitted TX. */
    RAISE_ERROR_STR("FI_MORE flush could not be submitted after 64 attempts; deferred source buffers remain owned");
}

/* Safe only before counting a new/unaccepted operation. Counters include all
 * previous writes, atomics, markers and fetching operations on this queue.
 * This only admits TX credits: CQ events still own individual payloads. */
static inline void
shmem_transport_ofi_more_admit(shmem_transport_ctx_t *ctx, size_t needed)
{
    shmem_internal_assert(needed <= ctx->put_more.budget);
    shmem_transport_ofi_more_flush(ctx, OFI_MORE_CREDIT);
    bool waited = false;
    for (;;) {
        uint64_t puts = shmem_transport_ofi_read_put_counter(ctx);
        uint64_t gets = fi_cntr_read(ctx->get_cntr);
        if (fi_cntr_readerr(ctx->get_cntr))
            RAISE_ERROR_STR("OFI get counter error during FI_MORE admission");
        uint64_t get_goal = SHMEM_TRANSPORT_OFI_CNTR_READ(&ctx->pending_get_cntr);
        shmem_internal_assert(puts <= ctx->put_cntr_pending && gets <= get_goal);
        uint64_t put_remaining = ctx->put_cntr_pending - puts;
        uint64_t get_remaining = get_goal - gets;
        size_t available = ctx->put_more.budget - needed;
        if (ctx->put_more.stats) ctx->put_more.admission_polls++;
        /* Separate comparisons avoid overflowing a sum of issued counters. */
        if (put_remaining <= available &&
            get_remaining <= available - put_remaining) {
            ctx->put_more.tx_posts = put_remaining + get_remaining;
            return;
        }
        if (!waited && ctx->put_more.stats) ctx->put_more.admission_waits++;
        waited = true;
        shmem_transport_ofi_progress_put_counter(ctx);
    }
}

static inline void
shmem_transport_ofi_more_reserve(shmem_transport_ctx_t *ctx)
{
    /* No counter reads or waits for injected/direct operations outside a
     * deferred group. The next eligible bounce put admits its own group. */
    if (!ctx->put_more.count) return;
    if (ctx->put_more.tx_posts <= ctx->put_more.budget - 2) return;
    shmem_transport_ofi_more_admit(ctx, 2);
}

static inline bool
shmem_transport_ofi_more_prepare(shmem_transport_ctx_t *ctx, size_t bytes)
{
    if (!shmem_transport_ofi_more_eligible(&ctx->put_more, bytes)) return false;
    if (!ctx->put_more.count)
        shmem_transport_ofi_more_admit(ctx, ctx->put_more.limit + 2);
    return true;
}

#endif
