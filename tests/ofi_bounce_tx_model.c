/* Provider/free-list fixture for extracted production OFI helpers.
 * No target-side progress occurs: only same-peer delivery proof exposes weak
 * payloads. This model is not a provider capability or hardware test. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <errno.h>

#define FI_EAGAIN 11
#define FI_MORE UINT64_C(1)
#define FI_DELIVERY_COMPLETE UINT64_C(2)
#define FI_COMPLETION UINT64_C(4)
#define FI_FENCE UINT64_C(8)
#define FI_TRANSMIT_COMPLETE UINT64_C(16)
#define FI_INJECT UINT64_C(32)
#define SHMEM_CTX_PRIVATE 1
#define SHMEM_CTX_SERIALIZED 2
#define SHMEM_SIGNAL_ADD 1
#define FI_SUM 1
#define FI_ATOMIC_WRITE 2
#define FI_UINT64 3
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#ifndef WANT_TOTAL_DATA_ORDERING
#define WANT_TOTAL_DATA_ORDERING 1
#endif

typedef uint64_t fi_addr_t;
typedef struct { void *next; } shmem_free_list_item_t;
typedef uint64_t shmem_internal_cntr_t;
typedef struct { uint64_t nalloc; } shmem_free_list_t;
struct fid_cntr { uint64_t success, errors; };
struct fid_ep { int id; };
struct fid_cq { int id; };
struct fid_mr { int id; };
struct fi_context2 { void *internal[8]; };
struct fi_cq_entry { void *op_context; };
struct fi_rma_iov { uint64_t addr; size_t len; uint64_t key; };
struct fi_msg_rma {
    const struct iovec *msg_iov;
    void **desc;
    size_t iov_count;
    fi_addr_t addr;
    const struct fi_rma_iov *rma_iov;
    size_t rma_iov_count;
    void *context;
    uint64_t data;
};
struct fi_ioc { void *addr; size_t count; };
struct fi_rma_ioc { uint64_t addr; size_t count; uint64_t key; };
struct fi_msg_atomic {
    const struct fi_ioc *msg_iov;
    void **desc;
    size_t iov_count;
    fi_addr_t addr;
    const struct fi_rma_ioc *rma_iov;
    size_t rma_iov_count;
    int datatype, op;
    void *context;
    uint64_t data;
};
#include "production_types.inc"

#define PEERS 3
#define SLOTS 2
#define BYTES 4096
#define MAX_OPS 64
struct operation {
    const unsigned char *source;
    unsigned char *target;
    size_t bytes;
    int peer;
    void *context;
    uint64_t flags;
    bool transmitted, delivered, marker;
    unsigned char saved[8192];
};
static struct operation operations[MAX_OPS];
static size_t noperations;
static void *events[MAX_OPS];
static size_t nevents, event_head;
static unsigned char remote[PEERS][8][8192];
static unsigned char user[8193];
static unsigned char marker_address;
static void *shmem_internal_data_base = &marker_address;
static int user_descriptor, marker_descriptor, slot_descriptors[SLOTS];
static void *marker_desc = &marker_descriptor;
static union {
    max_align_t alignment;
    unsigned char storage[sizeof(shmem_transport_ofi_bounce_buffer_t) + 8192];
} slot_storage[SLOTS];
static bool allocated[SLOTS];
static struct fid_cntr put_counter, get_counter;
static struct fid_ep endpoint;
static struct fid_cq completion_queue;
static shmem_free_list_t pool;
static shmem_transport_ctx_t shmem_transport_ctx_default;
static shmem_transport_ctx_t *current = &shmem_transport_ctx_default;
static unsigned char dirty[PEERS];
static int peers[PEERS];
static unsigned int posts, retries, markers, resets, probes, frees, locks, bb_locks;
static unsigned int progress_calls;
static int reject_posts, fail_post;
static int shared_peer = -1;
static bool auto_progress, expect_error;
static jmp_buf failure;
static int shmem_internal_my_pe, shmem_transport_ofi_single_ep;
static size_t shmem_transport_ofi_max_bounce_buffers = SLOTS;
static size_t shmem_transport_ofi_bounce_buffer_size = 8192;
static size_t shmem_transport_ofi_max_buffered_send = 512;
static size_t shmem_transport_ofi_max_msg_size = 16384;
static uint64_t shmem_transport_ofi_max_poll = 100;
static struct {
    size_t OFI_CQ_BATCH_SIZE;
    bool OFI_PUT_BATCH_STATS;
} shmem_internal_params = { 2, true };

static shmem_transport_ofi_bounce_buffer_t *slot(size_t index)
{
    return (void *)slot_storage[index].storage;
}
static int slot_index(void *pointer)
{
    for (int i = 0; i < SLOTS; i++)
        if (pointer == slot((size_t)i)) return i;
    return -1;
}
static void model_error(const char *format, ...)
{
    if (expect_error) longjmp(failure, 1);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(43);
}
#define RAISE_ERROR_MSG(...) model_error(__VA_ARGS__)
#define RAISE_ERROR_STR(msg) model_error("%s\n", msg)
#define shmem_internal_assert assert
#define OFI_CTX_CHECK_ERROR(ctx,ret) do { \
    (void)(ctx); if (ret) model_error("provider error %d\n", (int)(ret)); \
} while (0)
#define SHMEM_TRANSPORT_OFI_CNTR_READ(p) (*(p))
#define SHMEM_TRANSPORT_OFI_CNTR_INC(p) (++*(p))
#define GET_DEST(pe) ((fi_addr_t)(pe))
#define GET_MR_DESC_ADDR(index) ((index) == 0 ? &marker_desc : NULL)
#define GET_MR_DESC(index) ((index) == 0 ? marker_desc : NULL)
#define SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(ctx) do { \
    assert((ctx)->bounce_buffers); assert(!bb_locks); bb_locks++; \
} while (0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(ctx) do { \
    (void)(ctx); assert(bb_locks == 1); bb_locks--; \
} while (0)
static void shmem_transport_ofi_ctx_lock(shmem_transport_ctx_t *ctx)
{
    assert(ctx == current && !locks);
    locks++;
}
static void shmem_transport_ofi_ctx_unlock(shmem_transport_ctx_t *ctx)
{
    assert(ctx == current && locks == 1 && !bb_locks);
    locks--;
}
#define SHMEM_TRANSPORT_OFI_CTX_LOCK(ctx) shmem_transport_ofi_ctx_lock(ctx)
#define SHMEM_TRANSPORT_OFI_CTX_UNLOCK(ctx) shmem_transport_ofi_ctx_unlock(ctx)

static int shmem_transport_ofi_get_mr_desc_index(const void *p)
{
    return p == shmem_internal_data_base ? 0 : 1;
}
static int shmem_internal_get_shr_rank(int pe)
{
    return pe == shared_peer ? 0 : -1;
}
static void shmem_transport_ofi_get_mr(const void *p, int pe,
                                      uint8_t **address, uint64_t *key)
{
    assert(pe >= 0 && pe < PEERS);
    *address = (uint8_t *)p;
    *key = 123;
}
static void *shmem_free_list_alloc(shmem_free_list_t *list)
{
    assert(bb_locks && list == &pool);
    for (int i = 0; i < SLOTS; i++)
        if (!allocated[i]) {
            allocated[i] = true;
            list->nalloc++;
            return slot((size_t)i);
        }
    return NULL;
}
static void shmem_free_list_free(shmem_free_list_t *list, void *buffer)
{
    int index = slot_index(buffer);
    assert(bb_locks && list == &pool && index >= 0);
    assert(allocated[index] && list->nalloc);
    allocated[index] = false;
    list->nalloc--;
    frees++;
}
static void enqueue(void *context)
{
    assert(nevents < MAX_OPS);
    events[nevents++] = context;
}
static void complete_source(size_t index)
{
    struct operation *op = &operations[index];
    assert(!op->marker && !op->transmitted);
    memcpy(op->saved, op->source, op->bytes);
    op->transmitted = true;
    if (op->flags & FI_TRANSMIT_COMPLETE) {
        put_counter.success++;
        assert(op->flags & FI_COMPLETION);
        enqueue(op->context);
    } else {
        memcpy(op->target, op->saved, op->bytes);
        op->delivered = true;
        put_counter.success++;
        if (op->flags & FI_COMPLETION) enqueue(op->context);
    }
}
static void deliver_marker(size_t index)
{
    struct operation *marker = &operations[index];
    assert(marker->marker && !marker->delivered);
    for (size_t i = 0; i < index; i++) {
        struct operation *op = &operations[i];
        if (op->peer != marker->peer || op->marker || op->delivered) continue;
        if (!op->transmitted) complete_source(i);
        memcpy(op->target, op->saved, op->bytes);
        op->delivered = true;
    }
    marker->delivered = true;
    put_counter.success++;
    enqueue(marker->context);
}
static void provider_progress(void)
{
    assert(++progress_calls < 10000);
    if (!auto_progress) return;
    for (size_t i = 0; i < noperations; i++) {
        struct operation *op = &operations[i];
        if (op->marker && !op->delivered) {
            deliver_marker(i);
            return;
        }
        if (!op->marker && !op->transmitted) {
            complete_source(i);
            return;
        }
    }
}
static ssize_t fi_cq_read(struct fid_cq *cq, void *entries, size_t count)
{
    assert(cq == &completion_queue && count > 0);
    if (event_head == nevents) provider_progress();
    if (event_head == nevents) return -FI_EAGAIN;
    struct fi_cq_entry *result = entries;
    size_t n = MIN(count, nevents - event_head);
    for (size_t i = 0; i < n; i++) result[i].op_context = events[event_head++];
    return (ssize_t)n;
}
static int fi_writemsg(struct fid_ep *ep, const struct fi_msg_rma *msg,
                      uint64_t flags)
{
    assert(locks && ep == &endpoint && !(flags & FI_MORE));
    assert(msg->iov_count == 1 && msg->rma_iov_count == 1);
    assert(msg->msg_iov->iov_len == msg->rma_iov->len);
    posts++;
    int index = slot_index(msg->context);
    if (index >= 0) {
        assert(allocated[index]);
        assert(msg->msg_iov->iov_base == slot((size_t)index)->data);
        assert(msg->desc && *msg->desc == &slot_descriptors[index]);
        assert(*msg->desc != &user_descriptor);
    }
    if (reject_posts) {
        reject_posts--;
        retries++;
        return -FI_EAGAIN;
    }
    if (fail_post) return fail_post;
    assert(noperations < MAX_OPS);
    struct operation *op = &operations[noperations++];
    *op = (struct operation){
        .source = msg->msg_iov->iov_base, .bytes = msg->msg_iov->iov_len,
        .target = (void *)(uintptr_t)msg->rma_iov->addr, .peer = (int)msg->addr,
        .context = msg->context, .flags = flags,
        .marker = !msg->msg_iov->iov_len && (flags & FI_COMPLETION) &&
                  (flags & FI_FENCE)
    };
    if (op->marker) {
        assert(flags == (FI_FENCE | FI_DELIVERY_COMPLETE | FI_COMPLETION));
        assert(op->source == shmem_internal_data_base);
        assert(msg->desc && *msg->desc == marker_desc);
        markers++;
    } else if (flags & FI_INJECT) {
        memcpy(op->saved, op->source, op->bytes);
        op->source = op->saved;
    }
    return 0;
}
static int fi_atomicmsg(struct fid_ep *ep, const struct fi_msg_atomic *msg,
                        uint64_t flags)
{
    assert(ep == &endpoint && locks && flags & FI_DELIVERY_COMPLETE);
    /* Observe before this control operation can expose its notification. */
    for (size_t i = 0; i < noperations; i++)
        assert(!(operations[i].flags & FI_TRANSMIT_COMPLETE) ||
               operations[i].delivered);
    *(uint64_t *)(uintptr_t)msg->rma_iov->addr = *(uint64_t *)msg->msg_iov->addr;
    put_counter.success++;
    return 0;
}
static int fi_read(struct fid_ep *ep, void *target, size_t bytes, void *desc,
                   fi_addr_t peer, uint64_t address, uint64_t key, void *context)
{
    (void)desc; (void)peer; (void)key; (void)context;
    assert(ep == &endpoint && locks);
    for (size_t i = 0; i < noperations; i++)
        assert(!(operations[i].flags & FI_TRANSMIT_COMPLETE) ||
               operations[i].delivered);
    memcpy(target, (void *)(uintptr_t)address, bytes);
    get_counter.success++;
    return 0;
}
static uint64_t fi_cntr_read(struct fid_cntr *counter) { return counter->success; }
static uint64_t fi_cntr_readerr(struct fid_cntr *counter) { return counter->errors; }
static int fi_cntr_set(struct fid_cntr *counter, uint64_t value)
{
    assert(counter == &put_counter && !value);
    /* Reset is local-stage accounting only; weak state must survive it. */
    for (size_t i = 0; i < noperations; i++)
        assert(operations[i].marker || operations[i].transmitted);
    counter->success = value;
    resets++;
    return 0;
}
static void shmem_transport_probe(void) { probes++; }
static void shmem_transport_get_wait(shmem_transport_ctx_t *ctx) { (void)ctx; }
static void shmem_transport_ofi_more_flush(shmem_transport_ctx_t *ctx, int reason)
{
    (void)reason; assert(!ctx->put_more.count && !ctx->put_more.limit);
}
static void shmem_transport_ofi_more_reserve(shmem_transport_ctx_t *ctx)
{
    assert(!ctx->put_more.limit);
}
static bool shmem_transport_ofi_more_prepare(shmem_transport_ctx_t *ctx,
                                            size_t bytes)
{
    (void)bytes; assert(!ctx->put_more.limit); return false;
}
static double shmem_transport_ofi_bounce_pool_now(void) { return 1.0; }

#include "production_helpers.inc"

/* Test cases are below the production includes so they call the actual route,
 * quiet, CQ retirement and ordering helpers rather than a model of them. */
static void setup(bool enabled)
{
    memset(operations, 0, sizeof(operations));
    memset(remote, 0, sizeof(remote));
    memset(allocated, 0, sizeof(allocated));
    memset(dirty, 0, sizeof(dirty));
    memset(peers, 0, sizeof(peers));
    put_counter = get_counter = (struct fid_cntr){0};
    pool = (shmem_free_list_t){0};
    noperations = nevents = event_head = 0;
    posts = retries = markers = resets = probes = frees = locks = bb_locks = 0;
    progress_calls = 0;
    reject_posts = fail_post = 0;
    shared_peer = -1;
    auto_progress = expect_error = false;
    shmem_transport_ofi_bounce_buffer_size = 8192;
    shmem_transport_ofi_max_buffered_send = 512;
    shmem_transport_ofi_max_msg_size = 16384;
    shmem_transport_ctx_default = (shmem_transport_ctx_t){
        .id = -1, .stx_idx = -1, .ep = &endpoint, .cq = &completion_queue,
        .put_cntr = &put_counter, .get_cntr = &get_counter,
        .put_cntr_limit = SHMEM_TRANSPORT_OFI_CXI_PUT_CNTR_MAX,
        .put_epoch_id = 1, .put_epoch_dirty = dirty, .put_epoch_pes = peers,
        .bounce_buffers = &pool, .bounce_tx_complete = enabled,
        .bounce_tx_marker_desc = marker_desc
    };
    for (size_t i = 0; i < SLOTS; i++) {
        memset(slot(i), 0, sizeof(*slot(i)) + 8192);
        slot(i)->frag.mytype = SHMEM_TRANSPORT_OFI_TYPE_BOUNCE;
        slot(i)->local_desc = &slot_descriptors[i];
    }
}
static void put(int pe, int target_slot, size_t bytes, unsigned char value)
{
    memset(user, value, bytes);
    long completion = 0;
    shmem_transport_put_nb(current, remote[pe][target_slot], user, bytes,
                           pe, &completion);
    assert(!completion);
    memset(user, 0xee, bytes);
    assert(!locks && !bb_locks);
}
static void drain(void)
{
    SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(current);
    shmem_transport_ofi_drain_cq(current);
    SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(current);
}
static bool visible(int pe, int target_slot, size_t bytes, unsigned char value)
{
    /* One CPU observation; no target SHMEM call or progress-until-correct loop. */
    for (size_t i = 0; i < bytes; i++)
        if (remote[pe][target_slot][i] != value) return false;
    return true;
}
static void quiet(void)
{
    auto_progress = true;
    shmem_transport_put_quiet(current);
    assert(!pool.nalloc && !locks && !bb_locks);
    assert(!current->bounce_tx_weak_pending && !current->put_epoch_npes);
    assert(!current->bounce_tx_marker.outstanding);
    for (int pe = 0; pe < PEERS; pe++) assert(!dirty[pe]);
    for (size_t i = 0; i < noperations; i++) assert(operations[i].delivered);
}
static void reuse(void)
{
    setup(true);
    put(1, 0, BYTES, 0x11);
    put(2, 0, BYTES, 0x22);
    assert(pool.nalloc == 2 && current->bounce_tx_weak_pending == 2);
    assert(operations[0].context == slot(0) && operations[1].context == slot(1));
    complete_source(1);
    drain();
    assert(allocated[0] && !allocated[1] && frees == 1);
    assert(current->bounce_tx_weak_pending == 2);
    assert(dirty[2] & SHMEM_OFI_PUT_EPOCH_WEAK);
    put(2, 1, BYTES, 0x33);
    assert(operations[2].context == slot(1)); /* Exact out-of-order slot reused. */
    complete_source(2);
    drain();
    complete_source(0);
    drain();
    assert(pool.nalloc == 0 && frees == 3);
    assert(current->pending_bb_cntr == 3 && current->completed_bb_cntr == 3);
    assert(current->bounce_tx_weak_pending == 2 && current->put_epoch_npes == 2);
    assert(visible(1, 0, BYTES, 0) && visible(2, 0, BYTES, 0));
    quiet();
    assert(markers == 2 && visible(1, 0, BYTES, 0x11));
    assert(visible(2, 0, BYTES, 0x22) && visible(2, 1, BYTES, 0x33));
}
static void quiet_epochs(void)
{
    for (int count = 1; count <= 2; count++) {
        for (int alternate = 0; alternate <= 1; alternate++) {
            setup(true);
            for (int i = 0; i < count; i++)
                put(alternate ? 1 + i : 1, i, BYTES, (unsigned char)(0x40 + i));
            for (int i = count - 1; i >= 0; i--) complete_source((size_t)i);
            drain();
            assert(put_counter.success == (uint64_t)count && !pool.nalloc);
            assert(visible(1, 0, BYTES, 0)); /* All TX events precede visibility. */
            quiet();
            unsigned int expected = alternate ? (unsigned int)count : 1;
            assert(markers == expected);
            assert(current->put_cntr_pending == count + expected);
            for (int i = 0; i < count; i++)
                assert(visible(alternate ? 1 + i : 1, i, BYTES,
                               (unsigned char)(0x40 + i)));
            quiet();
            assert(markers == expected); /* Empty quiet does not post a marker. */
            put(2, 2, BYTES, 0x55);
            quiet();
            assert(markers == expected + 1 && visible(2, 2, BYTES, 0x55));
        }
    }
}
static void mixed(void)
{
    setup(true);
    put(1, 0, BYTES, 0x61);
    /* The below-window buffered route still uses delivery CQ retirement.
     * Its conservative boundary must deliver older weak traffic first. */
    auto_progress = true;
    put(2, 0, 1024, 0x62);
    assert(!(operations[noperations - 1].flags & FI_TRANSMIT_COMPLETE));
    assert(operations[noperations - 1].flags & FI_DELIVERY_COMPLETE);
    put(2, 1, BYTES, 0x63);
    quiet();
    assert(visible(1, 0, BYTES, 0x61));
    assert(visible(2, 0, 1024, 0x62) && visible(2, 1, BYTES, 0x63));
}
static void failed_posts(void)
{
    setup(true);
    reject_posts = 2;
    put(1, 0, BYTES, 0x71);
    assert(posts == 3 && retries == 2 && noperations == 1);
    assert(pool.nalloc == 1 && frees == 0 && current->bounce_tx_weak_pending == 1);
    quiet();
    assert(visible(1, 0, BYTES, 0x71));

    setup(true);
    fail_post = -5;
    expect_error = true;
    if (!setjmp(failure)) {
        put(2, 0, BYTES, 0x72);
        assert(0);
    }
    /* Failure is fatal in production: it must not masquerade as accepted,
     * release an in-flight source, or establish a weak-delivery obligation. */
    assert(pool.nalloc == 1 && allocated[0] && frees == 0);
    assert(!noperations && !current->bounce_tx_weak_pending);

    setup(true);
    put(1, 0, BYTES, 0x73);
    complete_source(0); /* Only the older slot may retire during a new retry. */
    reject_posts = 2;
    put(2, 0, BYTES, 0x74);
    assert(retries == 2 && noperations == 2 && frees == 1);
    assert(!allocated[0] && allocated[1] && pool.nalloc == 1);
    assert(current->bounce_tx_weak_pending == 2);
    reject_posts = 2; /* Retrying a marker must not acknowledge the peer early. */
    quiet();
    assert(retries == 4 && markers == 2 && visible(2, 0, BYTES, 0x74));
    assert(current->put_cntr_pending == 4);

    setup(true);
    put(1, 0, BYTES, 0x75);
    complete_source(0);
    drain();
    fail_post = -5;
    expect_error = true;
    if (!setjmp(failure)) {
        shmem_transport_put_quiet(current);
        assert(0);
    }
    assert(!pool.nalloc && current->bounce_tx_weak_pending == 1);
    assert(dirty[1] & SHMEM_OFI_PUT_EPOCH_WEAK);
    assert(!markers && visible(1, 0, BYTES, 0));
}
static void pressure_rebase(void)
{
    setup(true);
    put(1, 0, BYTES, 0x81);
    put(2, 0, BYTES, 0x82);
    auto_progress = true;
    put(1, 1, BYTES, 0x83); /* Only TX progress is required for pool admission. */
    auto_progress = false;
    assert(frees >= 1 && !markers && current->bounce_tx_weak_pending == 2);
    assert(visible(1, 0, BYTES, 0) && visible(2, 0, BYTES, 0));
    quiet();
    assert(visible(1, 1, BYTES, 0x83));

    setup(true);
    put(1, 0, BYTES, 0x84);
    complete_source(0);
    drain();
    current->put_cntr_limit = current->put_cntr_pending;
    shmem_transport_ofi_ctx_lock(current);
    shmem_transport_ofi_ensure_put_counter_capacity(current);
    shmem_transport_ofi_ctx_unlock(current);
    assert(resets == 1 && !current->put_cntr_pending);
    assert(current->bounce_tx_weak_pending == 1);
    assert(dirty[1] & SHMEM_OFI_PUT_EPOCH_WEAK);
    assert(visible(1, 0, BYTES, 0));
    current->put_cntr_limit = SHMEM_TRANSPORT_OFI_CXI_PUT_CNTR_MAX;
    quiet();
    assert(markers == 1 && visible(1, 0, BYTES, 0x84));
}
static void ordering(void)
{
    setup(true);
    put(1, 0, BYTES, 0x91);
    auto_progress = true;
    shmem_transport_fence(current);
    assert(visible(1, 0, BYTES, 0x91) && markers == 1);

    setup(true);
    put(1, 0, BYTES, 0x92);
    auto_progress = true;
    uint64_t signal = 0;
    shmem_transport_put_signal_nbi(current, remote[1][1], user, 0,
                                   &signal, 7, 0, 1);
    assert(signal == 7 && visible(1, 0, BYTES, 0x92));

    setup(true);
    put(1, 0, BYTES, 0x93);
    auto_progress = true;
    memset(user, 0x94, 128);
    shmem_transport_put_scalar(current, remote[2][0], user, 128, 2);
    assert(visible(1, 0, BYTES, 0x93) && markers == 1);
    quiet();
    assert(visible(2, 0, 128, 0x94));

    setup(true);
    put(1, 0, BYTES, 0x95);
    auto_progress = true;
    unsigned char fetched[BYTES];
    shmem_transport_get(current, fetched, remote[1][0], BYTES, 1);
    assert(markers == 1 && current->pending_get_cntr == 1);
    for (size_t i = 0; i < BYTES; i++) assert(fetched[i] == 0x95);
}
static void routes(void)
{
    for (int enabled = 0; enabled <= 1; enabled++) {
        const size_t sizes[] = {128, 1024, 1025, 8192};
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            setup(enabled);
            put(1, 0, sizes[i], 0xa1);
            bool weak = enabled && sizes[i] > 1024;
            assert(!!(operations[0].flags & FI_TRANSMIT_COMPLETE) == weak);
            assert(!!current->bounce_tx_weak_pending == weak);
            assert(current->pending_put_cntr == 1);
            quiet();
            assert(visible(1, 0, sizes[i], 0xa1));
            assert(markers == (unsigned int)weak);
        }
    }
    setup(true);
    memset(user, 0xa2, BYTES);
    shmem_transport_put_nbi(current, remote[1][0], user, BYTES, 1);
    assert(!pool.nalloc && !current->bounce_tx_weak_pending);
    assert(operations[0].context == NULL);
    assert(operations[0].flags == FI_DELIVERY_COMPLETE);
    quiet();
    assert(visible(1, 0, BYTES, 0xa2) && !markers);

    setup(true);
    shared_peer = 1;
    put(1, 0, BYTES, 0xa3);
    assert(operations[0].flags == (FI_DELIVERY_COMPLETE | FI_COMPLETION));
    assert(!current->bounce_tx_weak_pending);
    quiet();
    assert(visible(1, 0, BYTES, 0xa3) && !markers);

    /* Test the production eligibility helper, including negotiated limits. */
    assert(!shmem_transport_ofi_bounce_tx_eligible(false, 4096, 512, 8192, 16384));
    assert(!shmem_transport_ofi_bounce_tx_eligible(true, 1024, 512, 8192, 16384));
    assert(shmem_transport_ofi_bounce_tx_eligible(true, 1025, 512, 8192, 16384));
    assert(shmem_transport_ofi_bounce_tx_eligible(true, 8192, 512, 8192, 16384));
    assert(!shmem_transport_ofi_bounce_tx_eligible(true, 8193, 512, 16384, 16384));
    assert(!shmem_transport_ofi_bounce_tx_eligible(true, 4096, 4096, 8192, 16384));
    assert(!shmem_transport_ofi_bounce_tx_eligible(true, 4096, 512, 2048, 16384));
    assert(!shmem_transport_ofi_bounce_tx_eligible(true, 4096, 512, 8192, 2048));
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    if (!strcmp(argv[1], "reuse")) reuse();
    else if (!strcmp(argv[1], "quiet")) quiet_epochs();
    else if (!strcmp(argv[1], "mixed")) mixed();
    else if (!strcmp(argv[1], "failure")) failed_posts();
    else if (!strcmp(argv[1], "pressure-rebase")) pressure_rebase();
    else if (!strcmp(argv[1], "ordering")) ordering();
    else if (!strcmp(argv[1], "routes")) routes();
    else if (!strcmp(argv[1], "teardown")) {
        setup(true);
        put(1, 0, BYTES, 0xac);
        complete_source(0);
        drain();
        assert(!pool.nalloc && current->bounce_tx_weak_pending == 1);
        auto_progress = true;
        production_destroy_preamble(NULL);
        production_destroy_preamble(current);
        assert(markers == 1 && visible(1, 0, BYTES, 0xac));
        assert(!current->bounce_tx_weak_pending);
        /* The mocked MR/endpoint could be closed now, not before this drain. */
        assert(!current->bounce_tx_marker.outstanding && !locks && !bb_locks);
    }
    else if (!strcmp(argv[1], "early-quiet")) {
        setup(true);
        put(1, 0, BYTES, 0xb1);
        complete_source(0);
        drain();
        assert(!pool.nalloc && put_counter.success == current->put_cntr_pending);
        /* The runner compiles both the real helper and a version mutated to
         * return early. The same observation must reject only the mutation. */
        auto_progress = true;
        shmem_transport_put_quiet(current);
        if (!visible(1, 0, BYTES, 0xb1)) {
            fprintf(stderr, "quiet-at-return mismatch: TX is not delivery\n");
            return 1;
        }
        return 0;
    } else assert(0);
    return 0;
}
