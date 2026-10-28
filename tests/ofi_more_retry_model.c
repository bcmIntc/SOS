/* Exercises the actual production flush/admission helpers with an explicitly
 * deferred provider, including EAGAIN and a permanently rejected terminator.
 * This is a local model, not CXI hardware qualification. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/uio.h>
#define FI_MORE UINT64_C(1)
#define FI_DELIVERY_COMPLETE UINT64_C(2)
#define FI_EAGAIN 11
#include "transport_ofi_more_state.h"

struct counter { uint64_t success, errors; };
struct fi_rma_iov { uint64_t addr; size_t len; uint64_t key; };
struct fi_msg_rma {
    const struct iovec *msg_iov; void **desc; size_t iov_count;
    uint64_t addr; const struct fi_rma_iov *rma_iov; size_t rma_iov_count;
};
typedef struct {
    shmem_transport_ofi_more_state_t put_more;
    uint64_t put_cntr_pending, put_cntr_limit, pending_get_cntr;
    struct counter *put_cntr, *get_cntr;
    void *bounce_buffers, *ep;
} shmem_transport_ctx_t;

static unsigned int rejects, posts, drains, progress, reads, locks;
static uint64_t put_step, get_step;
static bool fail_after_progress;
static bool expect_failure;
static jmp_buf failure;
static unsigned char data;
static void *shmem_internal_data_base = &data;
#define shmem_internal_assert assert
#define GET_MR_DESC_ADDR(index) ((void)(index), (void **)0)
static int shmem_transport_ofi_get_mr_desc_index(void *p) { (void)p; return 0; }
#define RAISE_ERROR_STR(message) do { \
    (void)(message); assert(expect_failure); longjmp(failure, 1); \
} while (0)
#define OFI_CTX_CHECK_ERROR(ctx,ret) do { \
    (void)(ctx); if(ret) RAISE_ERROR_STR("post error"); \
} while (0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx) do { \
    (void)(ctx); assert(!locks); locks++; \
} while (0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx) do { \
    (void)(ctx); assert(locks==1); locks--; \
} while (0)
#define SHMEM_TRANSPORT_OFI_CNTR_READ(p) (*(p))
static int fi_writemsg(void *ep, const struct fi_msg_rma *msg, uint64_t flags)
{
    (void)ep;
    assert(flags == FI_DELIVERY_COMPLETE);
    assert(msg->msg_iov->iov_len == 0 && msg->rma_iov->len == 0);
    posts++;
    if (rejects) { rejects--; return -FI_EAGAIN; }
    return 0;
}
static void shmem_transport_ofi_drain_cq(shmem_transport_ctx_t *ctx)
{
    assert(locks == (ctx->bounce_buffers ? 1u : 0u));
    drains++;
}
static void shmem_transport_probe(void) {}
static void shmem_transport_ofi_progress_put_counter(shmem_transport_ctx_t *ctx)
{
    assert(!ctx->put_more.count);
    progress++;
    ctx->put_cntr->success += put_step;
    ctx->get_cntr->success += get_step;
    if (fail_after_progress) ctx->get_cntr->errors = 1;
}
static uint64_t fi_cntr_read(struct counter *c) { reads++; return c->success; }
static uint64_t fi_cntr_readerr(struct counter *c) { return c->errors; }
static uint64_t shmem_transport_ofi_read_put_counter(shmem_transport_ctx_t *ctx)
{
    uint64_t completed = fi_cntr_read(ctx->put_cntr);
    if (fi_cntr_readerr(ctx->put_cntr)) RAISE_ERROR_STR("put counter error");
    return completed;
}
#include "transport_ofi_more.h"

static shmem_transport_ctx_t setup(struct counter *put, struct counter *get)
{
    rejects = posts = drains = progress = reads = locks = 0;
    put_step = get_step = 0;
    fail_after_progress = false;
    *put = *get = (struct counter){0};
    expect_failure = false;
    return (shmem_transport_ctx_t){
        .put_more = {.limit=4, .count=3, .budget=16, .stats=true,
                     .puts=3, .more=3, .tx_posts=3, .dest=9, .addr=8, .key=7},
        /* Includes one counted but unaccepted member; flushing must not wait. */
        .put_cntr_pending=4, .put_cntr_limit=5, .put_cntr=put, .get_cntr=get,
        .bounce_buffers=&data
    };
}
int main(void)
{
    static struct counter put, get; /* Progressed values survive failure longjmp. */
    static shmem_transport_ctx_t ctx; /* Defined values survive failure longjmp. */
    ctx = setup(&put, &get);
    rejects = 2;
    shmem_transport_ofi_more_flush(&ctx, OFI_MORE_RETRY);
    assert(posts==3 && drains==2 && progress==0 && reads==0 && locks==0);
    assert(ctx.put_cntr_pending==5 && ctx.put_more.tx_posts==4);
    assert(ctx.put_more.count==0 && ctx.put_more.batched_puts==3);
    assert(ctx.put_more.ends[OFI_MORE_RETRY]==1);
    shmem_transport_ofi_more_flush(&ctx, OFI_MORE_RETRY);
    assert(posts==3 && ctx.put_cntr_pending==5); /* Empty flush is a no-op. */

    ctx = setup(&put, &get);
    ctx.put_cntr_pending = 3; /* No unaccepted post in admission. */
    ctx.put_more.tx_posts = 15;
    shmem_transport_ofi_more_reserve(&ctx);
    assert(posts==1 && progress==0 && ctx.put_more.tx_posts==4);
    assert(ctx.put_more.ends[OFI_MORE_CREDIT]==1);

    /* Ordinary/injected traffic with no open group cannot trigger counter
     * reads or admission waits, regardless of its accumulated post count. */
    ctx = setup(&put, &get);
    ctx.put_more.count = 0;
    ctx.put_more.tx_posts = 1000;
    shmem_transport_ofi_more_reserve(&ctx);
    assert(posts==0 && progress==0 && reads==0);

    /* Opening admission accounts unfinished gets as well as writes, but
     * accepts enough completed credits without draining either counter. */
    ctx.put_cntr_pending = 20;
    ctx.put_cntr_limit = 32;
    ctx.pending_get_cntr = 3;
    put.success = 12;
    get.success = 1;
    assert(shmem_transport_ofi_more_prepare(&ctx, 1024));
    assert(ctx.put_more.tx_posts==10 && progress==0 && reads==2);
    assert(ctx.put_more.admission_waits==0);

    ctx = setup(&put, &get);
    ctx.put_more.count = 0;
    ctx.put_cntr_pending = 20;
    ctx.put_cntr_limit = 32;
    ctx.pending_get_cntr = 5;
    put.success = 6;
    get.success = 1;
    put_step = 4;
    get_step = 1;
    assert(shmem_transport_ofi_more_prepare(&ctx, 1024));
    assert(progress==2 && ctx.put_more.tx_posts==8);
    assert(put.success==14 && get.success==3); /* Both goals remain unfinished. */
    assert(ctx.put_more.admission_waits==1 && ctx.put_more.admission_polls==3);

    /* Excluded bounce sizes do not open an admission window. */
    ctx = setup(&put, &get);
    ctx.put_more.count = 0;
    ctx.put_more.min_bytes = 1024;
    ctx.put_more.max_bytes = 4096;
    assert(!shmem_transport_ofi_more_prepare(&ctx, 512));
    assert(!shmem_transport_ofi_more_prepare(&ctx, 8192));
    assert(reads==0 && progress==0);
    ctx.put_more.count = 3;
    assert(!shmem_transport_ofi_more_prepare(&ctx, 8192));
    assert(ctx.put_more.count==3 && reads==0 && progress==0);
    shmem_transport_ofi_more_accept(&ctx.put_more, true, 0, OFI_MORE_FULL);
    assert(ctx.put_more.count==0); /* The accepted excluded payload submits it. */

    /* Counter errors must be rejected even if there would be enough space. */
    for (int which = 0; which < 2; which++) {
        ctx = setup(&put, &get);
        ctx.put_more.count = 0;
        if (which) get.errors = 1;
        else put.errors = 1;
        expect_failure = true;
        if (!setjmp(failure)) {
            shmem_transport_ofi_more_prepare(&ctx, 1024);
            assert(0);
        }
        assert(progress==0);
    }

    ctx = setup(&put, &get);
    ctx.put_more.count = 0;
    ctx.put_cntr_pending = 20;
    ctx.put_cntr_limit = 32;
    fail_after_progress = expect_failure = true;
    if (!setjmp(failure)) {
        shmem_transport_ofi_more_prepare(&ctx, 1024);
        assert(0);
    }
    assert(progress==1 && get.errors==1);

    ctx = setup(&put, &get);
    rejects = 100;
    expect_failure = true;
    if (!setjmp(failure)) {
        shmem_transport_ofi_more_flush(&ctx, OFI_MORE_RETRY);
        assert(0);
    }
    assert(posts==64 && progress==0 && reads==0 && locks==0);
    /* A failed terminator never closes or accounts the retained source group. */
    assert(ctx.put_more.count==3 && ctx.put_more.batches==0);
    assert(ctx.put_cntr_pending==5);
    return 0;
}
