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
    struct counter *get_cntr;
    void *bounce_buffers, *ep;
} shmem_transport_ctx_t;

static unsigned int rejects, posts, drains, waits, locks;
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
{ (void)ctx; assert(0); } /* GET goal is already complete in these cases. */
static void shmem_transport_ofi_wait_put_counter(shmem_transport_ctx_t *ctx)
{ assert(!ctx->put_more.count); waits++; }
static uint64_t fi_cntr_read(struct counter *c) { return c->success; }
static uint64_t fi_cntr_readerr(struct counter *c) { return c->errors; }
#include "transport_ofi_more.h"

static shmem_transport_ctx_t setup(struct counter *get)
{
    rejects = posts = drains = waits = locks = 0;
    expect_failure = false;
    return (shmem_transport_ctx_t){
        .put_more = {.limit=4, .count=3, .budget=16, .stats=true,
                     .puts=3, .more=3, .tx_posts=3, .dest=9, .addr=8, .key=7},
        /* Includes one counted but unaccepted member; flushing must not wait. */
        .put_cntr_pending=4, .put_cntr_limit=5, .get_cntr=get,
        .bounce_buffers=&data
    };
}
int main(void)
{
    struct counter get = {0};
    static shmem_transport_ctx_t ctx; /* Defined values survive failure longjmp. */
    ctx = setup(&get);
    rejects = 2;
    shmem_transport_ofi_more_flush(&ctx, OFI_MORE_RETRY);
    assert(posts==3 && drains==2 && waits==0 && locks==0);
    assert(ctx.put_cntr_pending==5 && ctx.put_more.tx_posts==4);
    assert(ctx.put_more.count==0 && ctx.put_more.batched_puts==3);
    assert(ctx.put_more.ends[OFI_MORE_RETRY]==1);
    shmem_transport_ofi_more_flush(&ctx, OFI_MORE_RETRY);
    assert(posts==3 && ctx.put_cntr_pending==5); /* Empty flush is a no-op. */

    ctx = setup(&get);
    ctx.put_cntr_pending = 3; /* No unaccepted post in admission. */
    ctx.put_more.tx_posts = 15;
    shmem_transport_ofi_more_reserve(&ctx);
    assert(posts==1 && waits==1 && ctx.put_more.tx_posts==0);
    assert(ctx.put_more.ends[OFI_MORE_CREDIT]==1);

    ctx = setup(&get);
    ctx.put_cntr_pending = 3;
    ctx.put_more.count = 0;
    ctx.put_more.tx_posts = 15;
    shmem_transport_ofi_more_reserve(&ctx);
    assert(posts==0 && waits==1 && ctx.put_more.tx_posts==0);
    assert(ctx.put_more.admission_waits==1);
    assert(ctx.put_more.ends[OFI_MORE_CREDIT]==0);

    ctx = setup(&get);
    rejects = 100;
    expect_failure = true;
    if (!setjmp(failure)) {
        shmem_transport_ofi_more_flush(&ctx, OFI_MORE_RETRY);
        assert(0);
    }
    assert(posts==64 && waits==0 && locks==0);
    /* A failed terminator never closes or accounts the retained source group. */
    assert(ctx.put_more.count==3 && ctx.put_more.batches==0);
    assert(ctx.put_cntr_pending==5);
    return 0;
}
