/* Static-reviewable regression model for the real OFI counter helpers.
 * Build the explicit ofi_counter_wait_model target, then run it directly.
 * No MPI, CXI hardware, or libsma linkage is needed.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct fid_cntr {
    uint64_t success, errors;
    unsigned int reset_calls, reset_delay;
    bool resetting;
};

typedef struct {
    struct fid_cntr *put_cntr;
    uint64_t put_cntr_pending, put_cntr_limit;
    void *bounce_buffers;
} shmem_transport_ctx_t;

static jmp_buf failure;
static bool expect_failure, cq_error, reset_fails;
static unsigned int bb_locks, progress_calls, complete_after, error_after;
static uint64_t expected_reset_threshold;
static struct fid_cntr counter;

#define RAISE_ERROR_MSG(...) do { \
    assert(expect_failure); \
    longjmp(failure, 1); \
} while (0)
#define OFI_CTX_CHECK_ERROR(ctx, ret) do { \
    (void) (ctx); \
    if (ret) RAISE_ERROR_MSG("counter reset failed"); \
} while (0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx) do { \
    assert((ctx)->bounce_buffers); \
    assert(bb_locks == 0); \
    bb_locks++; \
} while (0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx) do { \
    (void) (ctx); \
    assert(bb_locks == 1); \
    bb_locks--; \
} while (0)

static void shmem_transport_ofi_drain_cq(shmem_transport_ctx_t *ctx)
{
    assert(bb_locks == (ctx->bounce_buffers ? 1u : 0u));
    progress_calls++;
    assert(progress_calls < 64); /* Regressions must not hang the model. */
    if (cq_error)
        RAISE_ERROR_MSG("queued CQ failure");
    if (complete_after && progress_calls >= complete_after)
        counter.success = ctx->put_cntr_pending;
    if (error_after && progress_calls >= error_after)
        counter.errors = 1;
}

static void shmem_transport_probe(void) {}
static uint64_t fi_cntr_readerr(struct fid_cntr *cntr) { return cntr->errors; }
static uint64_t fi_cntr_read(struct fid_cntr *cntr)
{
    if (cntr->resetting) {
        if (cntr->reset_delay)
            cntr->reset_delay--;
        else {
            cntr->success = 0;
            cntr->resetting = false;
        }
    }
    return cntr->success;
}
static int fi_cntr_set(struct fid_cntr *cntr, uint64_t value)
{
    assert(value == 0);
    assert(cntr->success >= expected_reset_threshold);
    assert(cntr->errors == 0);
    cntr->reset_calls++;
    if (reset_fails)
        return -1;
    cntr->resetting = true;
    return 0;
}

#include "transport_ofi_counter.h"

static shmem_transport_ctx_t setup(bool bounce)
{
    counter = (struct fid_cntr) {0};
    expect_failure = cq_error = reset_fails = false;
    expected_reset_threshold = 0;
    bb_locks = progress_calls = complete_after = error_after = 0;
    return (shmem_transport_ctx_t) {
        .put_cntr = &counter, .put_cntr_pending = 3,
        .put_cntr_limit = 4, .bounce_buffers = bounce ? &counter : NULL
    };
}

static void expect_wait_failure(shmem_transport_ctx_t *ctx)
{
    expect_failure = true;
    if (setjmp(failure) == 0) {
        shmem_transport_ofi_wait_put_counter(ctx);
        assert(!"wait returned despite delivery failure");
    }
    assert(counter.reset_calls == 0);
}

int main(void)
{
    for (unsigned int bounce = 0; bounce < 2; bounce++) {
        shmem_transport_ctx_t ctx = setup(bounce);
        counter.errors = 1; /* Failure exists before the wait starts. */
        expect_wait_failure(&ctx);

        ctx = setup(bounce);
        cq_error = true; /* CQ error must be consumed while waiting. */
        expect_wait_failure(&ctx);

        ctx = setup(bounce);
        error_after = 2; /* Error arrives during progress. */
        expect_wait_failure(&ctx);

        ctx = setup(bounce);
        complete_after = 3;
        shmem_transport_ofi_wait_put_counter(&ctx);
        assert(progress_calls >= 3 && bb_locks == 0);
        assert(counter.success == 3 && ctx.put_cntr_pending == 3);

        ctx = setup(bounce);
        counter.success = ctx.put_cntr_pending;
        counter.errors = 1; /* Errors take precedence over reached success. */
        expect_wait_failure(&ctx);

        ctx = setup(bounce);
        shmem_transport_ofi_ensure_put_counter_capacity(&ctx);
        assert(counter.reset_calls == 0 && progress_calls == 0);

        ctx = setup(bounce);
        ctx.put_cntr_pending = ctx.put_cntr_limit;
        expected_reset_threshold = ctx.put_cntr_limit;
        complete_after = 3;
        counter.reset_delay = 2; /* Reset is not immediately observable. */
        shmem_transport_ofi_ensure_put_counter_capacity(&ctx);
        assert(counter.reset_calls == 1 && counter.success == 0);
        assert(ctx.put_cntr_pending == 0 && !counter.resetting && bb_locks == 0);

        /* A new post after rebase must wait for its own delivery. */
        ctx.put_cntr_pending = 1;
        complete_after = progress_calls + 3;
        shmem_transport_ofi_wait_put_counter(&ctx);
        assert(counter.success == 1 && progress_calls >= complete_after);

        ctx = setup(bounce);
        ctx.put_cntr_pending = ctx.put_cntr_limit;
        expected_reset_threshold = counter.success = ctx.put_cntr_limit;
        reset_fails = expect_failure = true;
        if (setjmp(failure) == 0) {
            shmem_transport_ofi_ensure_put_counter_capacity(&ctx);
            assert(!"capacity check returned after failed reset");
        }
        assert(ctx.put_cntr_pending == ctx.put_cntr_limit);
        assert(counter.reset_calls == 1 && !counter.resetting);
    }
    puts("OFI counter wait and rebase model checks completed");
    return 0;
}
