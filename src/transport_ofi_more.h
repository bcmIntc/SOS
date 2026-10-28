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
        int ret = fi_writemsg(ctx->ep, &msg, FI_DELIVERY_COMPLETE);
        if (!ret) {
            shmem_transport_ofi_more_accept(&ctx->put_more, false, 0, reason);
            return;
        }
        if (ret != -FI_EAGAIN) OFI_CTX_CHECK_ERROR(ctx, ret);
        if (ctx->put_more.stats) ctx->put_more.retries++;
        if (ctx->bounce_buffers) SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx);
        shmem_transport_ofi_drain_cq(ctx);
        if (ctx->bounce_buffers) SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx);
        shmem_transport_probe();
    }
    /* TX/resource reservations are conservative, not a provider guarantee.
     * Fail with retained ownership rather than wait forever on unsubmitted TX. */
    RAISE_ERROR_STR("FI_MORE flush could not be submitted after 64 attempts; deferred source buffers remain owned");
}

static inline void
shmem_transport_ofi_more_reserve(shmem_transport_ctx_t *ctx)
{
    if (!ctx->put_more.limit) return;
    size_t needed = ctx->put_more.count ? 2 : ctx->put_more.limit + 2;
    if (ctx->put_more.tx_posts <= ctx->put_more.budget - needed) return;
    shmem_transport_ofi_more_flush(ctx, OFI_MORE_CREDIT);
    if (ctx->put_more.stats) ctx->put_more.admission_waits++;
    /* Called only before incrementing the next operation's issued count.
     * Snapshot all nonfetching and fetching operations before reusing credits. */
    shmem_transport_ofi_wait_put_counter(ctx);
    uint64_t goal = SHMEM_TRANSPORT_OFI_CNTR_READ(&ctx->pending_get_cntr);
    while (fi_cntr_read(ctx->get_cntr) < goal) {
        shmem_transport_ofi_progress_put_counter(ctx);
        if (fi_cntr_readerr(ctx->get_cntr))
            RAISE_ERROR_STR("OFI get counter error during FI_MORE admission");
    }
    if (fi_cntr_readerr(ctx->get_cntr))
        RAISE_ERROR_STR("OFI get counter error during FI_MORE admission");
    ctx->put_more.tx_posts = 0;
}

#endif
