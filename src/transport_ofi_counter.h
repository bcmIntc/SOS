/* OFI operation-counter helpers. Include after the context, CQ drain, probe,
 * and error/locking definitions. Callers hold the context lock; they must
 * not hold the bounce free-list lock or have an unaccepted post counted.
 */
#ifndef TRANSPORT_OFI_COUNTER_H
#define TRANSPORT_OFI_COUNTER_H

/* CXI success counters have 48 bits, even though fi_cntr uses uint64_t. */
#define SHMEM_TRANSPORT_OFI_CXI_PUT_CNTR_MAX ((UINT64_C(1) << 48) - 1)

static inline
void shmem_transport_ofi_progress_put_counter(shmem_transport_ctx_t *ctx)
{
    /* Progress and consume errors even when selective completion suppresses
     * successful write CQ entries. CQ-owned bounce buffers may complete here. */
    if (ctx->bounce_buffers) SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx);
    shmem_transport_ofi_drain_cq(ctx);
    if (ctx->bounce_buffers) SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx);
    shmem_transport_probe();
}

static inline
uint64_t shmem_transport_ofi_read_put_counter(shmem_transport_ctx_t *ctx)
{
    uint64_t completed = fi_cntr_read(ctx->put_cntr);
    uint64_t errors = fi_cntr_readerr(ctx->put_cntr);
    if (errors)
        RAISE_ERROR_MSG("OFI put delivery counter reports %"PRIu64" failed operation(s)\n",
                        errors);
    return completed;
}

static inline
void shmem_transport_ofi_wait_put_counter(shmem_transport_ctx_t *ctx)
{
#ifdef SHMEM_TRANSPORT_OFI_COUNTER_FLUSH
    SHMEM_TRANSPORT_OFI_COUNTER_FLUSH(ctx);
#endif
    /* Do not use an infinite fi_cntr_wait: some providers only detect errors
     * whose counter value changes after that wait starts. Check all errors on
     * every progress pass, including before accepting a reached threshold. */
    for (;;) {
        shmem_transport_ofi_progress_put_counter(ctx);
        if (shmem_transport_ofi_read_put_counter(ctx) >= ctx->put_cntr_pending)
            return;
    }
}

static inline
void shmem_transport_ofi_ensure_put_counter_capacity(shmem_transport_ctx_t *ctx)
{
    if (ctx->put_cntr_pending < ctx->put_cntr_limit)
        return;

    /* All old writes, atomics and terminal writes must reach their requested
     * completion stage before reset. TX-bounce counter reach is NOT remote
     * delivery: weak peer bits/count survive until fenced marker CQ proof.
     * Do not reset logical/statistical counts, epoch membership or retained
     * source ownership: completed counter-owned buffers can stay on their list.
     * No new fabric operation can be accepted while the context lock is held. */
    shmem_transport_ofi_wait_put_counter(ctx);
    int ret = fi_cntr_set(ctx->put_cntr, 0);
    OFI_CTX_CHECK_ERROR(ctx, ret);

    /* Reset may not be visible immediately. Observe zero before posting any
     * new write, so a delayed reset cannot erase its completion increment. */
    do {
        shmem_transport_ofi_progress_put_counter(ctx);
    } while (shmem_transport_ofi_read_put_counter(ctx) != 0);
    ctx->put_cntr_pending = 0;
}

#endif /* TRANSPORT_OFI_COUNTER_H */
