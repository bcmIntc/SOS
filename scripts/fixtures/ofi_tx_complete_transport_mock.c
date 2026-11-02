/* -*- C -*- */
/* Compile the real helpers as well as the real header's inline entry points. */
#include <stdlib.h>

static unsigned fixture_allocations, fixture_frees;

static void *payload_allocate(size_t size)
{
    return malloc(size);
}

static void payload_free(void *pointer)
{
    free(pointer);
}

static void *fixture_malloc(size_t size)
{
    void *pointer = malloc(size);
    if (pointer) ++fixture_allocations;
    return pointer;
}

static void *fixture_calloc(size_t count, size_t size)
{
    void *pointer = calloc(count, size);
    if (pointer) ++fixture_allocations;
    return pointer;
}

static void fixture_free(void *pointer)
{
    if (pointer) ++fixture_frees;
    free(pointer);
}

#define malloc fixture_malloc
#define calloc fixture_calloc
#define free fixture_free
#ifdef SOS_MOCK_BASELINE
#include "transport_ofi.c"
#define shmem_internal_put_signal_payload_nb shmem_internal_put_nb
#else
#include "../../src/transport_ofi.c"
#endif

int shmem_internal_my_pe;
int shmem_internal_num_pes = 4;
int shmem_internal_thread_level = SHMEM_THREAD_SINGLE;
void *shmem_internal_heap_base;
long shmem_internal_heap_length;
void *shmem_internal_data_base;
long shmem_internal_data_length;
struct shmem_internal_params_s shmem_internal_params;
uint64_t (*shmem_internal_gettid_fn)(void);

static const char *test_case;

#define CHECK(expression) do {                                                \
    if (!(expression)) {                                                     \
        fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__,                 \
                test_case, #expression);                                     \
        exit(2);                                                             \
    }                                                                        \
} while (0)

void shmem_runtime_abort(int status, const char message[])
{
    (void) message;
    exit(status);
}

shmem_free_list_t *shmem_free_list_init(size_t element_size,
                                       shmem_free_list_item_init_fn_t init_fn,
                                       size_t max_pool_cnt)
{
    CHECK(!"startup fixture must stop before bounce-pool allocation");
    return NULL;
}

int shmem_free_list_more(shmem_free_list_t *pool)
{
    (void) pool;
    CHECK(!"fixture pool must not grow");
    return 1;
}

void shmem_free_list_destroy(shmem_free_list_t *pool)
{
    (void) pool;
    CHECK(!"destroy fixture has no bounce pool");
}

enum { PES = 4, HEAP_SIZE = 65536, MAX_EVENTS = 512 };
static unsigned char heap[HEAP_SIZE], remote[PES][HEAP_SIZE];
static uint8_t *remote_bases[PES];
static uint64_t remote_keys[PES] = {11, 12, 13, 14};
static fi_addr_t addresses[PES] = {31, 47, 59, 71};
static int node_ranks[PES] = {-1, -1, -1, -1}, node_size;
#if USE_XPMEM
static struct shmem_transport_xpmem_peer_info_t xpmem_peers[PES];
struct shmem_transport_xpmem_peer_info_t *shmem_transport_xpmem_peers = xpmem_peers;
#endif

int shmem_runtime_get_node_rank(int pe)
{
    CHECK(pe >= 0 && pe < PES);
    return node_ranks[pe];
}

int shmem_runtime_get_node_size(void)
{
    return node_size;
}

int shmem_runtime_get_rank(void)
{
    return shmem_internal_my_pe;
}

struct event {
    char kind;
    size_t len;
    const void *source;
    uint64_t address, key, flags, expected;
    int pe;
};

struct operation {
    const unsigned char *source;
    unsigned char *transmitted;
    unsigned char injected[192];
    size_t len, offset;
    int pe;
    bool copied, done, transmit_only;
};

struct mock {
    shmem_transport_ctx_t ctx;
    struct fid_ep ep;
    struct fid_cq cq;
    struct fid_cntr put, get;
    struct event events[MAX_EVENTS];
    struct operation operations[MAX_EVENTS];
    unsigned event_count, operation_count, accepted, waits, cq_successes;
    unsigned closes, retry_count, retry_progress;
    uint64_t completed, get_completed;
    uint64_t caps;
    bool delivery_peers[PES], flush_waited;
    void *flush_context, *bounce_context, *rogue_context;
    bool rogue;
    char retry_kind, error_kind;
    bool wait_error, counter_error, cq_error;
};

static struct fi_ops_rma rma_ops;
static struct fi_ops_atomic atomic_ops;
static struct fi_ops_cq cq_ops;
static struct fi_ops_cntr cntr_ops;
static struct fi_ops fid_ops;
static struct fid_cq progress_cq;

static struct mock *from_ep(struct fid_ep *ep)
{
    return ep->fid.context;
}

static int peer_index(fi_addr_t destination)
{
    for (int pe = 0; pe < PES; ++pe)
        if (GET_DEST(pe) == destination) return pe;
    CHECK(!"unexpected AV destination");
    return -1;
}

static uint64_t target_address(int pe, size_t offset)
{
#ifdef ENABLE_MR_SCALABLE
    (void) pe;
#ifdef ENABLE_REMOTE_VIRTUAL_ADDRESSING
    return (uint64_t) (heap + offset);
#else
    return offset;
#endif
#else
#ifdef ENABLE_REMOTE_VIRTUAL_ADDRESSING
    (void) pe;
    return (uint64_t) (heap + offset);
#else
    return (uint64_t) (remote[pe] + offset);
#endif
#endif
}

static uint64_t target_key(int pe)
{
#ifdef ENABLE_MR_SCALABLE
    (void) pe;
#ifdef ENABLE_REMOTE_VIRTUAL_ADDRESSING
    return 0;
#else
    return 1;
#endif
#else
    return remote_keys[pe];
#endif
}

static size_t target_offset(int pe, uint64_t address, uint64_t key)
{
    CHECK(key == target_key(pe));
    uint64_t base = target_address(pe, 0);
    CHECK(address >= base && address - base < HEAP_SIZE);
    return address - base;
}

static void record(struct mock *mock, char kind, const void *source, size_t len,
                   fi_addr_t destination, uint64_t address, uint64_t key,
                   uint64_t flags)
{
    CHECK(mock->event_count < MAX_EVENTS);
    int pe = peer_index(destination);
    target_offset(pe, address, key);
    mock->events[mock->event_count++] = (struct event) {
        .kind = kind, .source = source, .len = len, .pe = pe,
        .address = address, .key = key, .flags = flags
    };
}

static bool fail_post(struct mock *mock, char kind)
{
    if (mock->error_kind == kind) return true;
    if (mock->retry_kind == kind) {
        mock->retry_kind = 0;
        ++mock->retry_count;
        return true;
    }
    return false;
}

static int post_error(struct mock *mock, char kind)
{
    return mock->error_kind == kind ? -FI_EIO : -FI_EAGAIN;
}

static void queue_data(struct mock *mock, const void *source, size_t len,
                       fi_addr_t destination, uint64_t address, uint64_t key,
                       uint64_t flags)
{
    CHECK(mock->operation_count < MAX_EVENTS);
    struct operation *operation = &mock->operations[mock->operation_count++];
    operation->source = source;
    operation->len = len;
    operation->pe = peer_index(destination);
    operation->offset = target_offset(operation->pe, address, key);
    CHECK(operation->offset + len <= HEAP_SIZE);
    operation->copied = flags & FI_INJECT;
    operation->transmit_only = flags & FI_TRANSMIT_COMPLETE;
    if (operation->copied) {
        CHECK(len <= sizeof(operation->injected));
        memcpy(operation->injected, source, len);
    }
}

static void consume_data(struct mock *mock)
{
    for (unsigned i = 0; i < mock->operation_count; ++i) {
        struct operation *operation = &mock->operations[i];
        if (operation->done) continue;
        if (!operation->copied && !operation->transmitted) {
            operation->transmitted = payload_allocate(operation->len);
            CHECK(operation->transmitted);
            memcpy(operation->transmitted, operation->source, operation->len);
        }
        if (operation->transmit_only && !mock->delivery_peers[operation->pe])
            continue;
        memcpy(remote[operation->pe] + operation->offset,
               operation->copied ? operation->injected : operation->transmitted,
               operation->len);
        payload_free(operation->transmitted);
        operation->transmitted = NULL;
        operation->done = true;
    }
    memset(mock->delivery_peers, 0, sizeof(mock->delivery_peers));
    mock->completed = mock->accepted;
}

static ssize_t write_message(struct fid_ep *ep, const struct fi_msg_rma *msg,
                             uint64_t flags)
{
    struct mock *mock = from_ep(ep);
    if ((flags & FI_FENCE) && !(mock->caps & FI_FENCE))
        return -FI_EINVAL;
    CHECK(msg->iov_count == 1 && msg->rma_iov_count == 1);
    size_t len = msg->msg_iov[0].iov_len;
    CHECK(msg->rma_iov[0].len == len);
    char kind = len ? 'P' : 'F';
    if (fail_post(mock, kind)) return post_error(mock, kind);
    record(mock, kind, msg->msg_iov[0].iov_base, len, msg->addr,
           msg->rma_iov[0].addr, msg->rma_iov[0].key, flags);
    ++mock->accepted;
    if (len) {
        queue_data(mock, msg->msg_iov[0].iov_base, len, msg->addr,
                   msg->rma_iov[0].addr, msg->rma_iov[0].key, flags);
        if (flags & FI_COMPLETION) {
            CHECK(!mock->bounce_context);
            mock->bounce_context = msg->context;
        }
    } else {
        CHECK(flags == (FI_FENCE | FI_DELIVERY_COMPLETE | FI_COMPLETION));
        CHECK(!mock->flush_context);
        mock->flush_context = msg->context;
        mock->flush_waited = false;
        mock->delivery_peers[peer_index(msg->addr)] = true;
    }
    return 0;
}

static ssize_t inject_write(struct fid_ep *ep, const void *source, size_t len,
                            fi_addr_t destination, uint64_t address, uint64_t key)
{
    struct mock *mock = from_ep(ep);
    char kind = len ? 'S' : 'I';
    if (fail_post(mock, kind)) return post_error(mock, kind);
    record(mock, kind, source, len, destination, address, key, 0);
    ++mock->accepted;
    if (len) {
        queue_data(mock, source, len, destination, address, key,
                   FI_DELIVERY_COMPLETE | FI_INJECT);
    }
    return 0;
}

static ssize_t regular_write(struct fid_ep *ep, const void *source, size_t len,
                             void *desc, fi_addr_t destination, uint64_t address,
                             uint64_t key, void *context)
{
    struct mock *mock = from_ep(ep);
    record(mock, 'L', source, len, destination, address, key, 0);
    ++mock->accepted;
    queue_data(mock, source, len, destination, address, key, FI_DELIVERY_COMPLETE);
    return 0;
}

static ssize_t regular_read(struct fid_ep *ep, void *target, size_t len,
                            void *desc, fi_addr_t destination, uint64_t address,
                            uint64_t key, void *context)
{
    struct mock *mock = from_ep(ep);
    record(mock, 'R', target, len, destination, address, key, 0);
    memcpy(target, remote[peer_index(destination)] +
           target_offset(peer_index(destination), address, key), len);
    ++mock->get_completed;
    return 0;
}

static ssize_t inject_atomic(struct fid_ep *ep, const void *source, size_t count,
                             fi_addr_t destination, uint64_t address, uint64_t key,
                             enum fi_datatype datatype, enum fi_op op)
{
    struct mock *mock = from_ep(ep);
    CHECK(count == 1 && datatype == FI_UINT64 && op == FI_SUM);
    record(mock, 'A', source, sizeof(uint64_t), destination, address, key, 0);
    ++mock->accepted;
    return 0;
}

static ssize_t atomic_message(struct fid_ep *ep, const struct fi_msg_atomic *msg,
                              uint64_t flags)
{
    struct mock *mock = from_ep(ep);
    CHECK(flags & FI_DELIVERY_COMPLETE);
    CHECK(!(flags & FI_TRANSMIT_COMPLETE));
    CHECK(msg->datatype == FI_UINT64 && msg->iov_count == 1 &&
          msg->rma_iov_count == 1);
    CHECK(msg->msg_iov->count == msg->rma_iov->count);
    record(mock, 'A', msg->msg_iov->addr, sizeof(uint64_t) * msg->msg_iov->count, msg->addr,
           msg->rma_iov->addr, msg->rma_iov->key, flags);
    ++mock->accepted;
    return 0;
}

static int atomic_valid(struct fid_ep *ep, enum fi_datatype datatype,
                        enum fi_op operation, size_t *count)
{
    CHECK(datatype == FI_UINT64 && operation == FI_SUM);
    *count = 4;
    return 0;
}

static ssize_t cq_read(struct fid_cq *cq, void *buffer, size_t count)
{
    if (cq == &progress_cq) return -FI_EAGAIN;
    struct mock *mock = cq->fid.context;
    CHECK(count == 1);
    if (mock->cq_error) return -FI_EIO;
    if (mock->rogue) {
        mock->rogue = false;
        ((struct fi_cq_entry *) buffer)->op_context = mock->rogue_context;
        return 1;
    }
    if (mock->bounce_context) {
        ((struct fi_cq_entry *) buffer)->op_context = mock->bounce_context;
        consume_data(mock);
        mock->bounce_context = NULL;
        ++mock->cq_successes;
        return 1;
    }
    if (!mock->flush_context || !mock->flush_waited)
        return -FI_EAGAIN;
    ((struct fi_cq_entry *) buffer)->op_context = mock->flush_context;
    mock->flush_context = NULL;
    ++mock->cq_successes;
    return 1;
}

static ssize_t cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *error,
                         uint64_t flags)
{
    struct mock *mock = cq->fid.context;
    ++mock->retry_progress;
    return -FI_EAGAIN;
}

static uint64_t counter_read(struct fid_cntr *counter)
{
    struct mock *mock = counter->fid.context;
    return counter == &mock->put ? mock->completed : mock->get_completed;
}

static uint64_t counter_readerr(struct fid_cntr *counter)
{
    struct mock *mock = counter->fid.context;
    return mock->counter_error ? 1 : 0;
}

static int counter_wait(struct fid_cntr *counter, uint64_t expected, int timeout)
{
    struct mock *mock = counter->fid.context;
    CHECK(timeout == -1);
    if (counter == &mock->get) {
        CHECK(expected <= mock->get_completed);
        return 0;
    }
    CHECK(mock->event_count < MAX_EVENTS);
    mock->events[mock->event_count++] = (struct event) {
        .kind = 'W', .expected = expected
    };
    ++mock->waits;
    if (mock->wait_error) return -FI_EIO;
    CHECK(expected == mock->accepted);
    consume_data(mock);
    if (mock->flush_context) {
        mock->flush_waited = true;
    }
    return 0;
}

static int close_fid(struct fid *fid)
{
    struct mock *mock = fid->context;
#ifndef SOS_MOCK_BASELINE
    CHECK(!mock->ctx.cxi_tx_complete_peers && !mock->flush_context);
#else
    CHECK(!mock->flush_context);
    CHECK(!mock->bounce_context);
#endif
    CHECK(mock->completed == mock->accepted);
    ++mock->closes;
    return 0;
}

static void init_mock(struct mock *mock)
{
    memset(mock, 0, sizeof(*mock));
    mock->ep.fid.context = mock->cq.fid.context = mock;
    mock->put.fid.context = mock->get.fid.context = mock;
    mock->ep.fid.ops = mock->cq.fid.ops = &fid_ops;
    mock->put.fid.ops = mock->get.fid.ops = &fid_ops;
    mock->ep.rma = &rma_ops;
    mock->ep.atomic = &atomic_ops;
    mock->cq.ops = &cq_ops;
    mock->put.ops = mock->get.ops = &cntr_ops;
    mock->ctx.options = SHMEM_CTX_PRIVATE;
    mock->ctx.id = -1;
    mock->ctx.stx_idx = -1;
    mock->ctx.ep = &mock->ep;
    mock->ctx.cq = &mock->cq;
    mock->ctx.put_cntr = &mock->put;
    mock->ctx.get_cntr = &mock->get;
#ifndef SOS_MOCK_BASELINE
    if (shmem_transport_ofi_cxi_tx_complete_puts) {
        mock->caps = FI_FENCE;
        mock->ctx.cxi_tx_complete_flush_frag.mytype = SHMEM_TRANSPORT_OFI_TYPE_TX_COMPLETE_FLUSH;
    }
#endif
#ifdef USE_CTX_LOCK
    SHMEM_MUTEX_INIT(mock->ctx.lock);
#elif defined(ENABLE_THREADS) && !defined(SOS_MOCK_BASELINE)
    if (shmem_transport_ofi_cxi_tx_complete_puts)
        SHMEM_MUTEX_INIT(mock->ctx.cxi_tx_complete_lock);
#endif
}

static void destroy_mock_lock(struct mock *mock)
{
#ifndef SOS_MOCK_BASELINE
    if (shmem_transport_ofi_cxi_tx_complete_puts) {
        free(mock->ctx.cxi_tx_complete_peer_cache);
        mock->ctx.cxi_tx_complete_peer_cache = NULL;
    }
#endif
#ifdef USE_CTX_LOCK
    SHMEM_MUTEX_DESTROY(mock->ctx.lock);
#elif defined(ENABLE_THREADS) && !defined(SOS_MOCK_BASELINE)
    if (shmem_transport_ofi_cxi_tx_complete_puts)
        SHMEM_MUTEX_DESTROY(mock->ctx.cxi_tx_complete_lock);
#endif
}

static void reset_trace(struct mock *mock)
{
    mock->event_count = 0;
}

static void expect_trace(struct mock *mock, const char *expected)
{
    char actual[MAX_EVENTS + 1];
    for (unsigned i = 0; i < mock->event_count; ++i)
        actual[i] = mock->events[i].kind;
    actual[mock->event_count] = '\0';
    if (strcmp(actual, expected)) {
        fprintf(stderr, "%s: expected %s, got %s\n", test_case, expected, actual);
        exit(2);
    }
}

static void expect_accounted(struct mock *mock)
{
    CHECK(SHMEM_TRANSPORT_OFI_CNTR_READ(&mock->ctx.pending_put_cntr) ==
          mock->accepted);
    CHECK(mock->completed == mock->accepted);
    CHECK(!mock->flush_context);
#ifndef SOS_MOCK_BASELINE
    CHECK(!mock->ctx.cxi_tx_complete_peers);
#endif
    CHECK(mock->ctx.pending_bb_cntr == mock->ctx.completed_bb_cntr);
    for (unsigned i = 0; i < mock->operation_count; ++i) {
        CHECK(mock->operations[i].done);
        CHECK(!mock->operations[i].transmitted);
    }
}

#ifndef SOS_MOCK_BASELINE
static unsigned pending_peer_count(const struct mock *mock)
{
    return mock->ctx.cxi_tx_complete_peers_hashed ?
        HASH_COUNT(mock->ctx.cxi_tx_complete_peers) : !!mock->ctx.cxi_tx_complete_peers;
}

static void bulk(struct mock *mock, size_t offset, const void *source,
                 size_t len, int pe, bool nbi)
{
    long completion = 0;
    if (nbi)
        shmem_internal_put_nbi((shmem_ctx_t) &mock->ctx, heap + offset, source, len, pe);
    else {
        shmem_internal_put_nb((shmem_ctx_t) &mock->ctx, heap + offset, source, len, pe,
                             &completion);
        CHECK(completion == 0);
        unsigned before = mock->event_count;
        shmem_transport_put_wait(&mock->ctx, &completion);
        CHECK(mock->event_count == before);
    }
}

static void boundaries(void)
{
    const size_t lengths[] = {
        0, 1, 16, 192, 193, 256, 4096, 8191, 8192, 8193, 16384, 32768
    };
    unsigned char local[32768], saved[32768];
    for (int nbi = 0; nbi <= 1; ++nbi) {
        for (int symmetric = 0; symmetric <= 1; ++symmetric) {
            for (unsigned l = 0; l < sizeof(lengths) / sizeof(lengths[0]); ++l) {
                struct mock mock;
                init_mock(&mock);
                size_t len = lengths[l];
                unsigned char *source = symmetric ? heap + 32768 : local;
                for (size_t i = 0; i < len; ++i) source[i] = (i * 17 + 3) % 251;
                memcpy(saved, source, len);
                memset(remote[2] + 256, 0, len);
                bulk(&mock, 256, source, len, 2, nbi);
                unsigned pieces = !!len;
                CHECK(mock.accepted == pieces);
                bool inject = len && len <= shmem_transport_ofi_max_buffered_send;
                CHECK(mock.waits == (unsigned) (len && !inject && !nbi));
                for (unsigned i = 0; i < pieces; ++i) {
                    const struct event *event = &mock.events[i];
                    CHECK(event->kind == (inject ? 'S' : 'P') && event->len == len);
                    CHECK(event->source == source);
                    CHECK(event->address == target_address(2, 256));
                    CHECK(event->key == target_key(2) && event->pe == 2);
                    CHECK(event->flags == (inject ? 0 : FI_TRANSMIT_COMPLETE));
                }
                /* TX completion permits source reuse but not target visibility.
                 * NBI sources remain live until quiet. */
                if (!nbi || inject) memset(source, 0xee, len);
                if (len && !inject) CHECK(remote[2][256] == 0);
                if (nbi) CHECK(mock.completed == 0);
                reset_trace(&mock);
                shmem_transport_put_quiet(&mock.ctx);
                expect_trace(&mock, !len || inject ? "W" : "FW");
                for (unsigned i = 0; i < mock.event_count; ++i) {
                    const struct event *event = &mock.events[i];
                    if (event->kind != 'F') continue;
                    CHECK(event->source == heap && event->len == 0);
                    CHECK(event->pe == 2 && event->key == target_key(2));
                    CHECK(event->address == target_address(2, 256));
                }
                CHECK(memcmp(remote[2] + 256, saved, len) == 0);
                expect_accounted(&mock);
                CHECK(mock.cq_successes == (unsigned) (len != 0 && !inject));
                unsigned cq_before = mock.cq_successes;
                reset_trace(&mock);
                shmem_transport_put_quiet(&mock.ctx);
                expect_trace(&mock, "W");
                CHECK(mock.cq_successes == cq_before);
                destroy_mock_lock(&mock);
            }
        }
    }
}

static void hybrid_window(void)
{
    const size_t lengths[] = {
        1, 192, 193, 512, 1024, 1025, 2048, 4096, 8192, 8193, 16384
    };
    const struct {
        size_t lower, upper, inject;
        const char *kinds;
    } policies[] = {
        {1024, 8192, 192, "SSLLLPPPPLL"},
        {512, 4096, 192, "SSLLPPPPLLL"},
        {0, 64, 192, "SSLLLLLLLLL"},
        {0, 8192, 0, "PPPPPPPPPLL"}
    };
    unsigned char source[16384], saved[16384];
    for (unsigned p = 0; p < sizeof(policies) / sizeof(policies[0]); ++p) {
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF = policies[p].lower;
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF = policies[p].upper;
        shmem_transport_ofi_max_buffered_send = policies[p].inject;
        for (int nbi = 0; nbi <= 1; ++nbi) {
            for (unsigned l = 0; l < sizeof(lengths) / sizeof(lengths[0]); ++l) {
                struct mock mock;
                init_mock(&mock);
                size_t len = lengths[l];
                char kind = policies[p].kinds[l];
                memset(source, 0x37, len);
                memcpy(saved, source, len);
                memset(remote[2] + 256, 0, len);
                long completion = 0;
                if (nbi)
                    shmem_internal_put_nbi((shmem_ctx_t) &mock.ctx,
                                           heap + 256, source, len, 2);
                else {
                    shmem_internal_put_nb((shmem_ctx_t) &mock.ctx,
                                          heap + 256, source, len, 2, &completion);
                    CHECK(completion == (kind == 'L'));
                    shmem_transport_put_wait(&mock.ctx, &completion);
                    CHECK(completion == 0);
                }
                CHECK(mock.accepted == 1);
                CHECK(mock.events[0].kind == kind && mock.events[0].len == len);
                CHECK(mock.events[0].source == source);
                CHECK(mock.events[0].address == target_address(2, 256));
                if (kind == 'P') CHECK(mock.events[0].flags == FI_TRANSMIT_COMPLETE);
                CHECK(mock.waits == (unsigned) (!nbi && kind != 'S'));
                if (nbi || kind != 'L') CHECK(remote[2][256] == 0);
                if (!nbi || kind == 'S') memset(source, 0xee, len);
                reset_trace(&mock);
                shmem_transport_put_quiet(&mock.ctx);
                expect_trace(&mock, kind == 'P' ? "FW" : "W");
                if (kind != 'P') CHECK(!mock.ctx.cxi_tx_complete_peer_cache);
                CHECK(!memcmp(remote[2] + 256, saved, len));
                expect_accounted(&mock);
                destroy_mock_lock(&mock);
            }
        }
    }
}

static void hybrid_bounce(void)
{
    struct mock mock;
    init_mock(&mock);
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF = 1024;
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF = 8192;
    shmem_transport_ofi_bounce_buffer_size = 1024;
    shmem_transport_ofi_max_bounce_buffers = 1;
    shmem_transport_ofi_bounce_buffer_t *buffer = calloc(1, sizeof(*buffer) + 1024);
    CHECK(buffer);
    buffer->frag.mytype = SHMEM_TRANSPORT_OFI_TYPE_BOUNCE;
    shmem_free_list_t pool = {0};
    pool.head = &buffer->frag.item;
    mock.ctx.bounce_buffers = &pool;
    unsigned char source[512];
    memset(source, 0x51, sizeof(source));
    memset(heap + 32768, 0x6b, 4096);
    bulk(&mock, 4096, heap + 32768, 4096, 1, true);
    long completion = 0;
    shmem_internal_put_nb((shmem_ctx_t) &mock.ctx, heap + 256,
                          source, sizeof(source), 2, &completion);
    CHECK(completion == 0 && pool.nalloc == 1 && mock.waits == 0);
    expect_trace(&mock, "PP");
    CHECK(mock.events[1].flags == (FI_COMPLETION | FI_DELIVERY_COMPLETE));
    CHECK(mock.events[1].source == buffer->data);
    memset(source, 0xee, sizeof(source));
    shmem_transport_put_quiet(&mock.ctx);
    expect_trace(&mock, "PPFW");
    CHECK(pool.nalloc == 0 && remote[2][256] == 0x51);
    CHECK(!memcmp(remote[1] + 4096, heap + 32768, 4096));
    expect_accounted(&mock);
    mock.ctx.bounce_buffers = NULL;
    free(buffer);
    destroy_mock_lock(&mock);
}

static void hybrid_injection_ordering(void)
{
    struct mock mock;
    init_mock(&mock);
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF = 1024;
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF = 8192;
    memset(heap + 32768, 0x6b, 4096);
    bulk(&mock, 4096, heap + 32768, 4096, 1, true);
    CHECK(pending_peer_count(&mock) == 1);
    reset_trace(&mock);
    bulk(&mock, 256, heap + 32768, 16, 2, false);
    expect_trace(&mock, "FWS");
    CHECK(!pending_peer_count(&mock));
    CHECK(!memcmp(remote[1] + 4096, heap + 32768, 4096));
    reset_trace(&mock);
    shmem_transport_put_quiet(&mock.ctx);
    expect_trace(&mock, "W");
    expect_accounted(&mock);
    destroy_mock_lock(&mock);
}

static void hybrid_fragmentation(void)
{
    for (int nbi = 0; nbi <= 1; ++nbi) {
        struct mock mock;
        init_mock(&mock);
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF = 0;
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF = 32768;
        shmem_transport_ofi_max_msg_size = 1024;
        memset(heap + 32768, 0x6b, 2049);
        bulk(&mock, 4096, heap + 32768, 512, 1, true);
        reset_trace(&mock);
        long completion = 0;
        if (nbi)
            shmem_internal_put_nbi((shmem_ctx_t) &mock.ctx,
                                   heap + 8192, heap + 32768, 2049, 2);
        else
            shmem_internal_put_nb((shmem_ctx_t) &mock.ctx,
                                  heap + 8192, heap + 32768, 2049, 2, &completion);
        expect_trace(&mock, "FWLLL");
        for (unsigned i = 0; i < 3; ++i) {
            const struct event *event = &mock.events[i + 2];
            CHECK(event->len == (i == 2 ? 1 : 1024));
            CHECK(event->source == heap + 32768 + i * 1024);
            CHECK(event->address == target_address(2, 8192 + i * 1024));
        }
        CHECK(completion == !nbi);
        shmem_transport_put_wait(&mock.ctx, &completion);
        CHECK(completion == 0);
        shmem_transport_put_quiet(&mock.ctx);
        CHECK(!memcmp(remote[2] + 8192, heap + 32768, 2049));
        CHECK(!memcmp(remote[1] + 4096, heap + 32768, 512));
        expect_accounted(&mock);
        destroy_mock_lock(&mock);
    }
}

static void mixed(void)
{
    struct mock first, second;
    init_mock(&first);
    init_mock(&second);
    memset(heap + 32768, 0x6b, 16384);
    memset(heap + 33024, 0xa5, 193);
    bulk(&first, 256, heap + 32768, 193, 1, true);
    bulk(&first, 768, heap + 33024, 193, 2, true);
    bulk(&first, 1024, heap + 32768, 16, 3, true);
    bulk(&second, 2048, heap + 32768, 16, 2, true);
    CHECK(pending_peer_count(&first) == 3);
    CHECK(pending_peer_count(&second) == 1);
    reset_trace(&first);
    shmem_transport_put_quiet(&first.ctx);
    expect_trace(&first, "FWFWFW");
    expect_accounted(&first);
    CHECK(second.completed == 0 && second.event_count == 1);
    CHECK(pending_peer_count(&second) == 1);
    shmem_transport_put_quiet(&second.ctx);
    expect_accounted(&second);

    /* Different sizes to one peer coalesce without an intermediate drain. */
    reset_trace(&first);
    bulk(&first, 4096, heap + 32768, 16, 1, true);
    bulk(&first, 4200, heap + 33024, 192, 1, true);
    CHECK(pending_peer_count(&first) == 1);
    reset_trace(&first);
    shmem_transport_put_quiet(&first.ctx);
    expect_trace(&first, "FW");
    CHECK(!memcmp(remote[1] + 4096, heap + 32768, 16));
    CHECK(!memcmp(remote[1] + 4200, heap + 33024, 192));

    bulk(&first, 4096, heap + 32768, 16, 1, true);
    reset_trace(&first);
    bulk(&first, 4200, heap + 33024, 193, 1, true);
    expect_trace(&first, "P");
    reset_trace(&first);
    bulk(&first, 8192, heap + 32768, 8192, 1, false);
    expect_trace(&first, "PW");
    reset_trace(&first);
    shmem_transport_put_quiet(&first.ctx);
    expect_trace(&first, "FW");

    /* Blocking source completion is context-wide, not remote quiet. */
    bulk(&first, 4096, heap + 32768, 193, 1, true);
    bulk(&first, 4608, heap + 33024, 193, 2, true);
    bulk(&first, 8192, heap + 32768, 8192, 3, true);
    reset_trace(&first);
    bulk(&first, 16384, heap + 40960, 8193, 0, false);
    expect_trace(&first, "PW");
    CHECK(pending_peer_count(&first) == 4);
    reset_trace(&first);
    shmem_transport_put_quiet(&first.ctx);
    expect_trace(&first, "FWFWFWFW");
    expect_accounted(&first);
    CHECK(!memcmp(remote[0] + 16384, heap + 40960, 8193));
    CHECK(!memcmp(remote[3] + 8192, heap + 32768, 8192));

    bulk(&first, 256, heap + 32768, 16, 1, true);
    bulk(&first, 8192, heap + 32768, 8192, 2, true);
    reset_trace(&first);
    shmem_transport_put_quiet(&first.ctx);
    expect_trace(&first, "FWFW");
    expect_accounted(&first);

    /* Reposting after a source wait must retain the peer's delivery obligation. */
    bulk(&first, 256, heap + 32768, 193, 1, true);
    bulk(&first, 8192, heap + 32768, 8192, 2, false);
    bulk(&first, 768, heap + 33024, 193, 1, true);
    reset_trace(&first);
    shmem_transport_put_quiet(&first.ctx);
    expect_trace(&first, "FWFW");
    expect_accounted(&first);
    CHECK(!memcmp(remote[1] + 768, heap + 33024, 193));
    destroy_mock_lock(&first);
    destroy_mock_lock(&second);
}

static void peer_cache(void)
{
    struct mock mock;
    init_mock(&mock);
    memset(heap + 32768, 0x6b, 8192);
    unsigned allocations = fixture_allocations, frees = fixture_frees;
    bulk(&mock, 256, heap + 32768, 16, 1, true);
    struct shmem_transport_ofi_cxi_tx_complete_peer *cached = mock.ctx.cxi_tx_complete_peer_cache;
    CHECK(cached && mock.ctx.cxi_tx_complete_peers == cached);
    CHECK(!mock.ctx.cxi_tx_complete_peers_hashed);
    CHECK(fixture_allocations == allocations + 1);
    shmem_transport_put_quiet(&mock.ctx);
    expect_accounted(&mock);
    CHECK(fixture_frees == frees);
    allocations = fixture_allocations;

    const size_t lengths[] = {16, 193, 8192};
    for (unsigned i = 0; i < 12; ++i) {
        size_t length = lengths[i % 3];
        int pe = 1 + i % 2;
        reset_trace(&mock);
        bulk(&mock, 256, heap + 32768, length, pe, false);
        reset_trace(&mock);
        shmem_transport_put_quiet(&mock.ctx);
        expect_trace(&mock, "FW");
        CHECK(!memcmp(remote[pe] + 256, heap + 32768, length));
        expect_accounted(&mock);
        CHECK(mock.ctx.cxi_tx_complete_peer_cache == cached);
        CHECK(!mock.ctx.cxi_tx_complete_peers_hashed);
        CHECK(fixture_allocations == allocations && fixture_frees == frees);
    }

    reset_trace(&mock);
    for (int pe = 1; pe < PES; ++pe)
        bulk(&mock, 256, heap + 32768, 16, pe, true);
    CHECK(mock.ctx.cxi_tx_complete_peers_hashed && pending_peer_count(&mock) == 3);
    CHECK(fixture_allocations == allocations + 4);
    reset_trace(&mock);
    shmem_transport_put_quiet(&mock.ctx);
    expect_trace(&mock, "FWFWFW");
    expect_accounted(&mock);
    CHECK(fixture_frees == frees + 4);
    CHECK(mock.ctx.cxi_tx_complete_peer_cache == cached && !mock.ctx.cxi_tx_complete_peers_hashed);

    allocations = fixture_allocations;
    frees = fixture_frees;
    for (unsigned i = 0; i < 4; ++i) {
        reset_trace(&mock);
        bulk(&mock, 256, heap + 32768, 193, 2, true);
        shmem_transport_put_quiet(&mock.ctx);
        expect_accounted(&mock);
        CHECK(fixture_allocations == allocations && fixture_frees == frees);
    }
    shmem_transport_ctx_destroy(&mock.ctx);
    CHECK(!mock.ctx.cxi_tx_complete_peer_cache && fixture_frees == frees + 1);
}

static void controls(void)
{
    const char *operations[] = {"scalar", "fallback", "get", "atomic", "atomicv",
                                "signal", "signal-payload", "fence", "quiet"};
    for (unsigned i = 0; i < sizeof(operations) / sizeof(operations[0]); ++i) {
        struct mock mock;
        init_mock(&mock);
        mock.ctx.options = 0;
        memset(heap + 32768, 0x3c, 8193);
        bulk(&mock, 4096, heap + 32768, 193, 1, true);
        reset_trace(&mock);
        if (!strcmp(operations[i], "scalar")) {
            shmem_internal_put_scalar((shmem_ctx_t) &mock.ctx, heap + 256,
                                      heap + 32768, 8, 2);
#ifdef DISABLE_OFI_INJECT
            expect_trace(&mock, "FWPW");
            CHECK(mock.events[2].flags == FI_DELIVERY_COMPLETE);
#else
            expect_trace(&mock, "FWS");
#endif
        } else if (!strcmp(operations[i], "fallback")) {
            shmem_transport_ofi_put_control(&mock.ctx, heap + 256, heap + 32768, 8, 2);
            expect_trace(&mock, "FWPW");
            CHECK(mock.events[2].flags == FI_DELIVERY_COMPLETE);
        } else if (!strcmp(operations[i], "get")) {
            shmem_transport_get(&mock.ctx, heap + 512, heap + 4096, 8, 1);
            expect_trace(&mock, "FWR");
            CHECK(!memcmp(heap + 512, heap + 32768, 8));
            shmem_transport_get_wait(&mock.ctx);
        } else if (!strcmp(operations[i], "atomic")) {
            shmem_transport_atomic(&mock.ctx, heap + 256, heap + 32768, 8, 2,
                                   FI_SUM, SHM_INTERNAL_UINT64);
            expect_trace(&mock, "FWA");
            CHECK(mock.events[2].flags == (FI_DELIVERY_COMPLETE | FI_INJECT));
        } else if (!strcmp(operations[i], "atomicv")) {
            long completion = 0;
            shmem_transport_atomicv(&mock.ctx, heap + 256, heap + 32768, 2, 8, 2,
                                    FI_SUM, SHM_INTERNAL_UINT64, &completion);
            expect_trace(&mock, "FWA");
            CHECK(mock.events[2].flags == (FI_DELIVERY_COMPLETE | FI_INJECT));
            reset_trace(&mock);
            bulk(&mock, 4096, heap + 32768, 193, 1, true);
            reset_trace(&mock);
            shmem_transport_atomicv(&mock.ctx, heap + 256, heap + 32768, 10, 8, 2,
                                    FI_SUM, SHM_INTERNAL_UINT64, &completion);
            expect_trace(&mock, "FWAAA");
            for (unsigned j = 2; j < mock.event_count; ++j) {
                CHECK(mock.events[j].flags == FI_DELIVERY_COMPLETE);
                CHECK(mock.events[j].address == target_address(2, 256 + (j - 2) * 32));
                CHECK(mock.events[j].len == (j == 4 ? 16 : 32));
            }
        } else if (!strcmp(operations[i], "signal")) {
            shmem_transport_put_signal_nbi(&mock.ctx, heap + 256, heap + 32768, 16,
                                           (uint64_t *) (heap + 512), 1,
                                           SHMEM_SIGNAL_SET, 2);
            CHECK(mock.event_count >= 4);
            CHECK(mock.events[2].kind == 'P' &&
                  mock.events[2].flags == (FI_DELIVERY_COMPLETE | FI_INJECT));
            CHECK(mock.events[mock.event_count - 1].kind == 'A');
            for (unsigned j = 0; j < mock.event_count; ++j)
                CHECK(!(mock.events[j].flags & FI_TRANSMIT_COMPLETE));
        } else if (!strcmp(operations[i], "signal-payload")) {
            long completion = 0;
            shmem_transport_ofi_max_msg_size = 256;
            shmem_internal_put_signal_payload_nb((shmem_ctx_t) &mock.ctx, heap + 8192,
                                                 heap + 32768, 8193, 2, &completion);
            CHECK(mock.event_count == 36 && completion == 0);
            CHECK(mock.events[35].kind == 'W');
            for (unsigned j = 0; j < 33; ++j) {
                const struct event *event = &mock.events[j + 2];
                CHECK(event->kind == 'P' && event->flags == FI_DELIVERY_COMPLETE);
                CHECK(event->len == (j == 32 ? 1 : 256));
                CHECK(event->source == heap + 32768 + j * 256);
                CHECK(event->address == target_address(2, 8192 + j * 256));
            }
            memset(heap + 32768, 0xff, 8193);
            CHECK(remote[2][8192] == 0x3c && remote[2][16384] == 0x3c);
            shmem_transport_ofi_max_msg_size = 32768;
        } else if (!strcmp(operations[i], "fence")) {
            shmem_transport_fence(&mock.ctx);
            expect_trace(&mock, "FW");
        } else {
            shmem_transport_quiet(&mock.ctx);
            expect_trace(&mock, "FW");
        }
        CHECK(!mock.ctx.cxi_tx_complete_peers);
        shmem_transport_quiet(&mock.ctx);
        expect_accounted(&mock);
        destroy_mock_lock(&mock);
    }
}

#endif

static void print_trace(const struct mock *mock)
{
    for (unsigned i = 0; i < mock->event_count; ++i) {
        const struct event *event = &mock->events[i];
        size_t offset = event->kind == 'W' ? 0 :
                        target_offset(event->pe, event->address, event->key);
        printf("%c:%zu:%d:%zu:%" PRIu64 ":%" PRIu64 ":%" PRIu64 "\n",
               event->kind, event->len, event->pe, offset, event->key,
               event->flags, event->expected);
    }
}

static void disabled(void)
{
    struct mock mock;
    init_mock(&mock);
    memset(heap + 32768, 0x51, 8193);
    long completion = 0;
    shmem_transport_put_nb(&mock.ctx, heap + 256, heap + 32768, 192, 1, &completion);
    shmem_transport_put_nbi(&mock.ctx, heap + 512, heap + 32768, 193, 2);
    shmem_transport_put_nb(&mock.ctx, heap + 8192, heap + 32768, 8192, 3, &completion);
    expect_trace(&mock, "SLL");
    CHECK(completion == 1 && mock.waits == 0);
#ifndef SOS_MOCK_BASELINE
    CHECK(!mock.ctx.cxi_tx_complete_peers);
#endif
    shmem_transport_put_wait(&mock.ctx, &completion);
    CHECK(completion == 0);
    expect_trace(&mock, "SLLW");
    expect_accounted(&mock);
    CHECK(!memcmp(remote[3] + 8192, heap + 32768, 8192));
    print_trace(&mock);

    shmem_transport_ofi_bounce_buffer_t *buffer = malloc(sizeof(*buffer) + 512);
    CHECK(buffer);
    memset(buffer, 0, sizeof(*buffer));
    buffer->frag.mytype = SHMEM_TRANSPORT_OFI_TYPE_BOUNCE;
    shmem_free_list_t pool = {0};
    pool.head = &buffer->frag.item;
    mock.ctx.bounce_buffers = &pool;
    shmem_transport_ofi_bounce_buffer_size = 512;
    shmem_transport_ofi_max_bounce_buffers = 1;
    reset_trace(&mock);
    shmem_transport_put_nb(&mock.ctx, heap + 2048, heap + 32768, 193, 2, &completion);
    CHECK(pool.nalloc == 1 && completion == 0);
    CHECK(!memcmp(buffer->data, heap + 32768, 193));
    CHECK(mock.events[0].flags == (FI_DELIVERY_COMPLETE | FI_COMPLETION));
    memset(heap + 32768, 0xaa, 193);
    shmem_transport_put_quiet(&mock.ctx);
    expect_trace(&mock, "PW");
    CHECK(pool.nalloc == 0 && pool.head == &buffer->frag.item);
    CHECK(mock.ctx.pending_bb_cntr == 1 && mock.ctx.completed_bb_cntr == 1);
    CHECK(remote[2][2048] == 0x51);
    expect_accounted(&mock);
    print_trace(&mock);
    free(buffer);
    destroy_mock_lock(&mock);
}

#ifndef SOS_MOCK_BASELINE
static void retries(void)
{
    const char stages[] = {'P', 'F'};
    for (unsigned i = 0; i < sizeof(stages); ++i) {
        struct mock mock;
        init_mock(&mock);
        mock.retry_kind = stages[i];
        bulk(&mock, 256, heap + 32768, 193, 1, true);
        shmem_transport_put_quiet(&mock.ctx);
        expect_trace(&mock, "PFW");
        CHECK(mock.retry_count == 1 && mock.retry_progress == 1);
        CHECK(mock.accepted == 2 && mock.cq_successes == 1);
        expect_accounted(&mock);
        destroy_mock_lock(&mock);
    }
}

static void destroy_context(void)
{
    const size_t lengths[] = {193, 8193};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        struct mock mock, other;
        init_mock(&mock);
        init_mock(&other);
        /* id=-1 avoids registering or allocating a team just for the fixture. */
        bulk(&mock, 256, heap + 32768, lengths[i], 1, true);
        bulk(&other, 16384, heap + 32768, 193, 2, true);
        reset_trace(&mock);
        shmem_transport_ctx_destroy(&mock.ctx);
        expect_trace(&mock, "FW");
        CHECK(mock.closes == 4);
        expect_accounted(&mock);
        CHECK(other.completed == 0 && other.closes == 0);
        CHECK(pending_peer_count(&other) == 1);
        shmem_transport_put_quiet(&other.ctx);
        expect_accounted(&other);
        destroy_mock_lock(&other);
    }
}

static void shared_controls(void)
{
#if USE_XPMEM
    struct mock mock;
    init_mock(&mock);
    mock.ctx.options = 0;
    node_ranks[0] = 0;
    node_size = 1;
    xpmem_peers[0].heap_ptr = heap;
    xpmem_peers[0].data_ptr = heap;
    shmem_ctx_t ctx = (shmem_ctx_t) &mock.ctx;
    uint64_t value = 7;
    memcpy(heap + 32768, &value, sizeof(value));
    bulk(&mock, 4096, heap + 32768, 193, 1, true);
    reset_trace(&mock);
    shmem_internal_put_scalar(ctx, heap + 256, &value, 8, 0);
    expect_trace(&mock, "FW");
    CHECK(!memcmp(heap + 256, &value, 8));
    CHECK(!mock.ctx.cxi_tx_complete_peers);

    bulk(&mock, 4096, heap + 32768, 193, 1, true);
    reset_trace(&mock);
    shmem_internal_get(ctx, heap + 512, heap + 256, 8, 0);
    expect_trace(&mock, "FW");
    CHECK(!memcmp(heap + 512, &value, 8));

    /* Shared data + NIC signal on a multi-node layout must unlock before
     * the recursive signal-only dispatch acquires the context lock. */
    bulk(&mock, 4096, heap + 32768, 193, 1, true);
    reset_trace(&mock);
    shmem_internal_put_signal_nbi(ctx, heap + 768, heap + 32768, 16,
                                  (uint64_t *) (heap + 1024), 9, SHMEM_SIGNAL_ADD, 0);
#if USE_HIERARCHICAL_BARRIER
    expect_trace(&mock, "FWA");
    CHECK(mock.events[2].flags == (FI_DELIVERY_COMPLETE | FI_INJECT));
#else
    expect_trace(&mock, "FW");
#endif
    CHECK(!memcmp(heap + 768, heap + 32768, 16));
    shmem_transport_put_quiet(&mock.ctx);

    /* In an all-local layout the CPU atomic must still drain NIC weak state.
     * The NIC operation here deliberately bypasses dispatch to seed that state. */
    for (int pe = 0; pe < PES; ++pe) {
        node_ranks[pe] = pe;
        xpmem_peers[pe].heap_ptr = heap;
        xpmem_peers[pe].data_ptr = heap;
    }
    node_size = PES;
    shmem_transport_put_nbi(&mock.ctx, heap + 4096, heap + 32768, 193, 1);
    reset_trace(&mock);
    shmem_internal_atomic(ctx, heap + 256, &value, 8, 0,
                          SHM_INTERNAL_SUM, SHM_INTERNAL_UINT64);
    expect_trace(&mock, "FW");
    uint64_t updated;
    memcpy(&updated, heap + 256, 8);
    CHECK(updated == 14);
    expect_accounted(&mock);
    destroy_mock_lock(&mock);
#else
    puts("shared controls require an existing XPMEM build");
#endif
}

static void reject_errors(const char *name)
{
    struct mock mock;
    init_mock(&mock);
    if (!strcmp(name, "error-payload")) mock.error_kind = 'P';
    bulk(&mock, 256, heap + 32768, 193, 1, true);
    if (!strcmp(name, "error-flush")) mock.error_kind = 'F';
    if (!strcmp(name, "missing-fence")) mock.caps = 0;
    if (!strcmp(name, "error-control")) {
        mock.error_kind = 'P';
        shmem_transport_ofi_put_control(&mock.ctx, heap + 512, heap + 32768, 8, 1);
        CHECK(!"control error must abort");
    }
    if (!strcmp(name, "error-wait")) mock.wait_error = true;
    if (!strcmp(name, "error-counter")) mock.counter_error = true;
    if (!strcmp(name, "error-cq")) mock.cq_error = true;
    shmem_transport_ofi_frag_t foreign = {0};
    foreign.mytype = SHMEM_TRANSPORT_OFI_TYPE_TX_COMPLETE_FLUSH;
    if (!strcmp(name, "bad-completion")) {
        mock.rogue = true;
        mock.rogue_context = NULL;
    } else if (!strcmp(name, "foreign-marker")) {
        mock.rogue = true;
        mock.rogue_context = &foreign;
    } else if (!strcmp(name, "wrong-marker")) {
        mock.ctx.cxi_tx_complete_flush_frag.mytype = SHMEM_TRANSPORT_OFI_TYPE_LONG;
    }
    shmem_transport_put_quiet(&mock.ctx);
    CHECK(!"error must abort");
}

static void validate_provider(const char *name)
{
    struct fi_tx_attr tx = { .inject_size = 192, .caps = FI_FENCE };
    struct fi_rx_attr rx = {0};
    struct fi_domain_attr domain = {
        .mr_mode = FI_MR_ENDPOINT, .threading = FI_THREAD_SAFE
    };
    struct fi_fabric_attr fabric = { .prov_name = "cxi" };
    struct fi_info selected = {
        .tx_attr = &tx, .rx_attr = &rx,
        .domain_attr = &domain, .fabric_attr = &fabric
    };
    shmem_transport_ofi_max_msg_size = 8192;
    if (!strcmp(name, "gate-provider")) fabric.prov_name = "tcp";
    if (!strcmp(name, "gate-fence")) tx.caps = 0;
    if (!strcmp(name, "gate-context")) selected.mode = FI_CONTEXT;
    if (!strcmp(name, "gate-context2")) selected.mode = FI_CONTEXT2;
    if (!strcmp(name, "gate-tx-context")) tx.mode = FI_CONTEXT;
    if (!strcmp(name, "gate-rx-context2")) rx.mode = FI_CONTEXT2;
    if (!strcmp(name, "gate-localmr")) domain.mr_mode |= FI_MR_LOCAL;
    if (!strcmp(name, "gate-hmem")) {
#ifdef FI_MR_HMEM
        domain.mr_mode |= FI_MR_HMEM;
#else
        CHECK(!"FI_MR_HMEM unavailable in configured headers");
#endif
    }
    if (!strcmp(name, "gate-maxmsg")) shmem_transport_ofi_max_msg_size = 0;
    if (!strcmp(name, "gate-valid-smallmsg")) shmem_transport_ofi_max_msg_size = 192;
    if (!strcmp(name, "gate-valid-multiple") ||
        !strcmp(name, "gate-thread-completion") ||
        !strcmp(name, "gate-thread-domain"))
        shmem_internal_thread_level = SHMEM_THREAD_MULTIPLE;
    if (!strcmp(name, "gate-valid-funneled")) {
        shmem_internal_thread_level = SHMEM_THREAD_FUNNELED;
        domain.threading = FI_THREAD_COMPLETION;
    }
    if (!strcmp(name, "gate-thread-completion"))
        domain.threading = FI_THREAD_COMPLETION;
    if (!strcmp(name, "gate-thread-domain")) domain.threading = FI_THREAD_DOMAIN;
    shmem_transport_ofi_cxi_tx_complete_validate(&selected);
    CHECK(!strcmp(name, "gate-valid") || !strcmp(name, "gate-valid-multiple") ||
          !strcmp(name, "gate-valid-funneled") || !strcmp(name, "gate-valid-smallmsg"));
}

#endif

static void disabled_controls(void)
{
    struct mock mock;
    init_mock(&mock);
    mock.ctx.options = 0;
    shmem_ctx_t ctx = (shmem_ctx_t) &mock.ctx;
    memset(heap + 32768, 0x29, 8193);
    long completion = 0;
    shmem_internal_put_scalar(ctx, heap + 256, heap + 32768, 8, 1);
    shmem_internal_put_signal_payload_nb(ctx, heap + 512, heap + 32768,
                                         193, 2, &completion);
    shmem_internal_put_wait(ctx, &completion);
    shmem_transport_get(&mock.ctx, heap + 8192, heap + 256, 8, 1);
    shmem_transport_get_wait(&mock.ctx);
    shmem_transport_atomic(&mock.ctx, heap + 768, heap + 32768, 8, 1,
                            FI_SUM, SHM_INTERNAL_UINT64);
    shmem_transport_put_signal_nbi(&mock.ctx, heap + 1024, heap + 32768, 16,
                                   (uint64_t *) (heap + 2048), 1,
                                   SHMEM_SIGNAL_ADD, 2);
    shmem_transport_fence(&mock.ctx);
    shmem_transport_quiet(&mock.ctx);
    expect_accounted(&mock);
    print_trace(&mock);
#if USE_XPMEM
    node_ranks[0] = 0;
    node_size = 1;
    xpmem_peers[0].heap_ptr = heap;
    xpmem_peers[0].data_ptr = heap;
    reset_trace(&mock);
    shmem_transport_put_nbi(&mock.ctx, heap + 4096, heap + 32768, 193, 1);
    unsigned before = mock.event_count;
    shmem_internal_put_scalar(ctx, heap + 256, heap + 32768, 8, 0);
    shmem_internal_get(ctx, heap + 512, heap + 256, 8, 0);
    shmem_internal_put_nbi(ctx, heap + 1024, heap + 32768, 16, 0);
    CHECK(mock.event_count == before);
    shmem_transport_quiet(&mock.ctx);
    expect_accounted(&mock);
    print_trace(&mock);
#endif
    reset_trace(&mock);
    shmem_transport_ctx_destroy(&mock.ctx);
    CHECK(mock.event_count == 0 && mock.closes == 4);
}

static uint64_t startup_flags;
static uint64_t startup_caps, startup_tx_caps, query_caps;
static bool startup_stop_at_endpoint;
static enum fi_cq_format startup_cq_format;
static struct fid_ep startup_ep;
static struct fid_cntr startup_counter;

int fi_getinfo(uint32_t version, const char *node, const char *service,
               uint64_t flags, const struct fi_info *hints, struct fi_info **info)
{
    query_caps = hints->caps;
    return -FI_EIO;
}

static void query_capabilities(void)
{
    struct fabric_info info = {0};
    bool enabled = false;
#ifndef SOS_MOCK_BASELINE
    enabled = shmem_transport_ofi_cxi_tx_complete_puts;
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS = enabled;
#endif
    CHECK(query_for_fabric(&info) == -FI_EIO);
#ifdef USE_FI_FENCE
    CHECK(query_caps & FI_FENCE);
#else
    CHECK(!!(query_caps & FI_FENCE) == enabled);
#endif
    printf("query_caps:%" PRIu64 "\n", query_caps);
}

static int startup_endpoint(struct fid_domain *domain, struct fi_info *info,
                             struct fid_ep **ep, void *context)
{
    startup_flags = info->tx_attr->op_flags;
    startup_caps = info->caps;
    startup_tx_caps = info->tx_attr->caps;
    if (startup_stop_at_endpoint)
        return -FI_EIO;
    startup_ep.fid.ops = &fid_ops;
    *ep = &startup_ep;
    return 0;
}

static int startup_bind(struct fid *fid, struct fid *resource, uint64_t flags)
{
    return 0;
}

static int startup_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
                           struct fid_cq **cq, void *context)
{
    startup_cq_format = attr->format;
    if (startup_stop_at_endpoint) {
        *cq = &progress_cq;
        return 0;
    }
    return -FI_EIO;
}

static int startup_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
                             struct fid_cntr **counter, void *context)
{
    *counter = &startup_counter;
    return 0;
}

static void startup(void)
{
    struct fi_tx_attr tx = {0};
    struct fi_rx_attr rx = {0};
    struct fi_ep_attr ep = {0};
    struct fi_info info = { .tx_attr = &tx, .rx_attr = &rx, .ep_attr = &ep };
    struct fi_ops_domain domain_ops = {
        .endpoint = startup_endpoint, .cq_open = startup_cq_open,
        .cntr_open = startup_cntr_open
    };
    struct fid_domain domain = { .ops = &domain_ops };
    struct fid_av av = {0};
    shmem_transport_ofi_info.p_info = &info;
    shmem_transport_ofi_domainfd = &domain;
    shmem_transport_ofi_avfd = &av;
    shmem_transport_ofi_single_ep = 1;
    fid_ops.bind = startup_bind;
    CHECK(shmem_transport_ofi_target_ep_init() == -FI_EIO);
#ifndef SOS_MOCK_BASELINE
    if (shmem_transport_ofi_cxi_tx_complete_puts) {
        CHECK(startup_flags == FI_DELIVERY_COMPLETE);
        CHECK(startup_cq_format == FI_CQ_FORMAT_CONTEXT);
        CHECK(startup_caps & FI_FENCE);
        CHECK(startup_tx_caps & FI_FENCE);
    } else
#endif
    {
        CHECK(startup_flags == 0);
        CHECK(startup_cq_format == FI_CQ_FORMAT_UNSPEC);
    }
    printf("startup:%" PRIu64 ":%d\n", startup_flags, startup_cq_format);
    startup_stop_at_endpoint = true;
    struct mock mock = {0};
    CHECK(shmem_transport_ofi_ctx_init(&mock.ctx, 1) == -FI_EIO);
#ifndef SOS_MOCK_BASELINE
    CHECK(!!(startup_caps & FI_FENCE) == shmem_transport_ofi_cxi_tx_complete_puts);
    CHECK(!!(startup_tx_caps & FI_FENCE) == shmem_transport_ofi_cxi_tx_complete_puts);
#else
    CHECK(!(startup_caps & FI_FENCE) && !(startup_tx_caps & FI_FENCE));
#endif
    printf("ctx_caps:%" PRIu64 ":%" PRIu64 "\n", startup_caps, startup_tx_caps);
    destroy_mock_lock(&mock);
}

#ifndef SOS_MOCK_BASELINE
static void reject_disabled_helper(const char *name)
{
    struct mock mock;
    init_mock(&mock);
    if (!strcmp(name, "disabled-put-helper"))
        shmem_transport_ofi_cxi_tx_complete_put_locked(&mock.ctx, heap + 256,
                                               heap + 32768, 16, 1, true);
    else if (!strcmp(name, "disabled-drain-helper"))
        shmem_transport_ofi_cxi_tx_complete_drain_locked(&mock.ctx);
    else
        shmem_transport_ofi_put_control(&mock.ctx, heap + 256, heap + 32768, 16, 1);
    CHECK(!"disabled helper must fail before posting");
}
#endif

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    test_case = argv[1];
    shmem_internal_heap_base = heap;
    shmem_internal_heap_length = sizeof(heap);
    for (int pe = 0; pe < PES; ++pe) remote_bases[pe] = remote[pe];
#ifndef ENABLE_MR_SCALABLE
    shmem_transport_ofi_target_heap_keys = remote_keys;
    shmem_transport_ofi_target_data_keys = remote_keys;
#ifdef ENABLE_REMOTE_VIRTUAL_ADDRESSING
    shmem_transport_ofi_use_absolute_address = 1;
#else
    shmem_transport_ofi_target_heap_addrs = remote_bases;
    shmem_transport_ofi_target_data_addrs = remote_bases;
#endif
#endif
    addr_table = addresses;
    shmem_transport_ofi_max_buffered_send = 192;
    shmem_transport_ofi_max_msg_size = 32768;
    shmem_transport_ofi_max_poll = 4;
#ifndef SOS_MOCK_BASELINE
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF = 0;
    shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF = 32768;
    if (strncmp(test_case, "disabled", 8))
        shmem_transport_ofi_cxi_tx_complete_puts = true;
    if (!strcmp(test_case, "boundaries") ||
        !strcmp(test_case, "mixed") ||
        !strcmp(test_case, "peer-cache"))
        shmem_transport_ofi_max_buffered_send = 0;
#endif
    SHMEM_Dtsize[FI_UINT64] = sizeof(uint64_t);
    rma_ops.writemsg = write_message;
    rma_ops.inject = inject_write;
    rma_ops.write = regular_write;
    rma_ops.read = regular_read;
    atomic_ops.inject = inject_atomic;
    atomic_ops.writemsg = atomic_message;
    atomic_ops.writevalid = atomic_valid;
    cq_ops.read = cq_read;
    cq_ops.readerr = cq_readerr;
    cntr_ops.read = counter_read;
    cntr_ops.readerr = counter_readerr;
    cntr_ops.wait = counter_wait;
    fid_ops.close = close_fid;
    progress_cq.ops = &cq_ops;
    shmem_transport_ofi_target_cq = &progress_cq;
    if (!strcmp(test_case, "disabled")) disabled();
    else if (!strcmp(test_case, "disabled-controls")) disabled_controls();
    else if (!strcmp(test_case, "disabled-startup")) startup();
    else if (!strcmp(test_case, "disabled-query")) query_capabilities();
#ifndef SOS_MOCK_BASELINE
    else if (!strcmp(test_case, "enabled-original")) {
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF = 32768;
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF = 65536;
        disabled();
    }
    else if (!strcmp(test_case, "enabled-startup")) startup();
    else if (!strcmp(test_case, "enabled-query")) query_capabilities();
    else if (!strcmp(test_case, "disabled-put-helper") ||
             !strcmp(test_case, "disabled-drain-helper") ||
             !strcmp(test_case, "disabled-control-helper")) reject_disabled_helper(test_case);
    else if (!strcmp(test_case, "boundaries")) boundaries();
    else if (!strcmp(test_case, "hybrid-window")) hybrid_window();
    else if (!strcmp(test_case, "hybrid-bounce")) hybrid_bounce();
    else if (!strcmp(test_case, "hybrid-injection-ordering")) hybrid_injection_ordering();
    else if (!strcmp(test_case, "hybrid-fragmentation")) hybrid_fragmentation();
    else if (!strcmp(test_case, "mixed")) mixed();
    else if (!strcmp(test_case, "peer-cache")) peer_cache();
    else if (!strcmp(test_case, "controls")) controls();
    else if (!strcmp(test_case, "retries")) retries();
    else if (!strcmp(test_case, "destroy")) destroy_context();
    else if (!strcmp(test_case, "shared-controls")) shared_controls();
    else if (!strncmp(test_case, "gate-", 5)) validate_provider(test_case);
    else reject_errors(test_case);
#else
    else CHECK(!"unexpected baseline case");
#endif
    return 0;
}
