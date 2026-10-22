/* Live CXI qualification of the shared SOS counter helpers. MPI bootstraps
 * addresses and checks payloads; it does not carry the test writes.
 * No production-library test knobs or OpenSHMEM private ABI are required.
 */
#include <mpi.h>
#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { BLOCKS = 17, EPOCHS = 16, TEST_LIMIT = 4 };
typedef struct {
    struct fid_cntr *put_cntr;
    uint64_t put_cntr_pending, put_cntr_limit;
    void *bounce_buffers;
    struct fid_cq *cq;
} shmem_transport_ctx_t;

static shmem_transport_ctx_t ctx;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static struct fid_ep *ep;
static struct fid_av *av;
static struct fid_mr *source_mr, *target_mr;
static struct fi_info *info;
static unsigned char *source, *target;
static uint64_t peer_address, peer_key;
static fi_addr_t peer;
static size_t bytes, buffer_size;
static int rank;
static jmp_buf expected_failure;
static bool catch_failure;
static unsigned int cq_errors, rebases;

static _Noreturn void fatal(const char *format, ...)
{
    va_list args;
    fprintf(stderr, "rank=%d ", rank);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
    if (catch_failure)
        longjmp(expected_failure, 1);
    MPI_Abort(MPI_COMM_WORLD, 1);
    abort();
}

#define RAISE_ERROR_MSG(...) fatal(__VA_ARGS__)
#define OFI_CTX_CHECK_ERROR(context, result) do { \
    (void) (context); \
    if (result) fatal("counter reset failed: %s\n", fi_strerror(-(result))); \
} while (0)
#define SHMEM_TRANSPORT_OFI_CTX_BB_LOCK(context) ((void) (context))
#define SHMEM_TRANSPORT_OFI_CTX_BB_UNLOCK(context) ((void) (context))

static void check(int result, const char *operation)
{
    if (result)
        fatal("%s failed: %s (%d)\n", operation, fi_strerror(-result), result);
}

static void shmem_transport_ofi_drain_cq(shmem_transport_ctx_t *context)
{
    struct fi_cq_entry completion;
    ssize_t result;
    while ((result = fi_cq_read(context->cq, &completion, 1)) > 0) {}
    if (result == -FI_EAVAIL) {
        struct fi_cq_err_entry error = {0};
        ssize_t count = fi_cq_readerr(context->cq, &error, 0);
        if (count != 1)
            fatal("CQ error read failed: %zd\n", count);
        cq_errors++;
        fatal("hardware CQ delivery error: err=%d prov_errno=%d\n",
              error.err, error.prov_errno);
    }
    if (result != -FI_EAGAIN)
        fatal("CQ read failed: %zd\n", result);
}

static void shmem_transport_probe(void) {}
#include "transport_ofi_counter.h"

/* Both ranks make fabric progress while waiting for MPI notifications, so
 * FI_PROGRESS_MANUAL target work is not dependent on MPI's progress engine. */
static void receive_token(int tag)
{
    int ready = 0;
    while (!ready) {
        shmem_transport_ofi_drain_cq(&ctx);
        (void) fi_cntr_read(ctx.put_cntr);
        MPI_Iprobe(1 - rank, tag, MPI_COMM_WORLD, &ready, MPI_STATUS_IGNORE);
    }
    MPI_Recv(NULL, 0, MPI_BYTE, 1 - rank, tag, MPI_COMM_WORLD,
             MPI_STATUS_IGNORE);
}

static void send_token(int tag)
{
    MPI_Send(NULL, 0, MPI_BYTE, 1 - rank, tag, MPI_COMM_WORLD);
}

static void register_memory(void *buffer, uint64_t access, uint64_t key,
                            struct fid_mr **mr)
{
    check(fi_mr_reg(domain, buffer, buffer_size, access, 0, key, 0, mr, NULL),
          "fi_mr_reg");
    if (info->domain_attr->mr_mode & FI_MR_ENDPOINT) {
        check(fi_mr_bind(*mr, &ep->fid, 0), "fi_mr_bind");
        check(fi_mr_enable(*mr), "fi_mr_enable");
    }
}

static void setup(void)
{
    struct fi_info *hints = fi_allocinfo();
    if (!hints) fatal("fi_allocinfo failed\n");
    hints->fabric_attr->prov_name = strdup("cxi");
    if (!hints->fabric_attr->prov_name) fatal("strdup failed\n");
    hints->ep_attr->type = FI_EP_RDM;
    hints->caps = FI_RMA | FI_READ | FI_WRITE | FI_REMOTE_READ |
                  FI_REMOTE_WRITE | FI_FENCE;
    /* Client-assigned keys are deliberately used here: provider-assigned
     * cached CXI keys may retain remote access after fi_close(MR).
     * A client key uses an actual hardware unlink when revoked. */
    hints->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR |
                                  FI_MR_ALLOCATED | FI_MR_ENDPOINT;
    hints->domain_attr->threading = FI_THREAD_DOMAIN;
    hints->domain_attr->data_progress = FI_PROGRESS_MANUAL;
    hints->domain_attr->control_progress = FI_PROGRESS_MANUAL;
    check(fi_getinfo(FI_VERSION(1, 15), NULL, NULL, 0, hints, &info),
          "fi_getinfo(cxi)");
    fi_freeinfo(hints);
    if (strcmp(info->fabric_attr->prov_name, "cxi"))
        fatal("test requires the cxi provider\n");
    if (info->domain_attr->mr_mode & (FI_MR_RAW | FI_MR_PROV_KEY))
        fatal("harness requires ordinary client-assigned MR keys\n");
    check(fi_fabric(info->fabric_attr, &fabric, NULL), "fi_fabric");
    check(fi_domain(fabric, info, &domain, NULL), "fi_domain");
    struct fi_av_attr av_attr = { .type = FI_AV_TABLE, .count = 2 };
    check(fi_av_open(domain, &av_attr, &av, NULL), "fi_av_open");
    struct fi_cq_attr cq_attr = {
        .format = FI_CQ_FORMAT_CONTEXT, .size = 8, .wait_obj = FI_WAIT_NONE
    };
    check(fi_cq_open(domain, &cq_attr, &ctx.cq, NULL), "fi_cq_open");
    struct fi_cntr_attr counter_attr = {
        .events = FI_CNTR_EVENTS_COMP, .wait_obj = FI_WAIT_UNSPEC
    };
    check(fi_cntr_open(domain, &counter_attr, &ctx.put_cntr, NULL),
          "fi_cntr_open");
    check(fi_endpoint(domain, info, &ep, NULL), "fi_endpoint");
    check(fi_ep_bind(ep, &av->fid, 0), "bind AV");
    check(fi_ep_bind(ep, &ctx.cq->fid,
                     FI_TRANSMIT | FI_RECV | FI_SELECTIVE_COMPLETION),
          "bind CQ");
    check(fi_ep_bind(ep, &ctx.put_cntr->fid, FI_WRITE), "bind counter");
    check(fi_enable(ep), "fi_enable");
    source = malloc(buffer_size);
    target = calloc(1, buffer_size);
    if (!source || !target) fatal("buffer allocation failed\n");
    register_memory(source, FI_READ | FI_WRITE, 1, &source_mr);
    register_memory(target, FI_REMOTE_READ | FI_REMOTE_WRITE, 2, &target_mr);

    size_t name_size = 0;
    int result = fi_getname(&ep->fid, NULL, &name_size);
    if (result != -FI_ETOOSMALL || !name_size || name_size > 4096)
        fatal("invalid endpoint address size: %zu (%d)\n", name_size, result);
    unsigned char local_name[4096], remote_name[4096];
    check(fi_getname(&ep->fid, local_name, &name_size), "fi_getname");
    unsigned long long local_size = name_size, remote_size = 0;
    MPI_Sendrecv(&local_size, 1, MPI_UNSIGNED_LONG_LONG, 1 - rank, 0,
                 &remote_size, 1, MPI_UNSIGNED_LONG_LONG, 1 - rank, 0,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    if (remote_size != local_size) fatal("endpoint address sizes differ\n");
    MPI_Sendrecv(local_name, (int) name_size, MPI_BYTE, 1 - rank, 1,
                 remote_name, (int) name_size, MPI_BYTE, 1 - rank, 1,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    if (fi_av_insert(av, remote_name, 1, &peer, 0, NULL) != 1)
        fatal("fi_av_insert failed\n");
    uint64_t metadata[2] = {
        (info->domain_attr->mr_mode & FI_MR_VIRT_ADDR) ?
            (uint64_t) (uintptr_t) target : 0,
        fi_mr_key(target_mr)
    }, remote_metadata[2];
    MPI_Sendrecv(metadata, sizeof(metadata), MPI_BYTE, 1 - rank, 2,
                 remote_metadata, sizeof(remote_metadata), MPI_BYTE, 1 - rank, 2,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    peer_address = remote_metadata[0];
    peer_key = remote_metadata[1];
    ctx.put_cntr_limit = TEST_LIMIT;
    uint32_t version = fi_version();
    printf("rank=%d provider=cxi domain=%s mr_mode=0x%x client_keys=1"
           " test_limit=%d bytes=%zu libfabric=%u.%u\n",
           rank, info->domain_attr->name, info->domain_attr->mr_mode,
           TEST_LIMIT, bytes, FI_MAJOR(version), FI_MINOR(version));
    fflush(stdout);
}

/* Capacity is checked before counting an operation, exactly as in SOS.
 * FI_EAGAIN retries neither recount the post nor change source ownership. */
static void post(unsigned int block, bool terminal)
{
    uint64_t before = ctx.put_cntr_pending;
    shmem_transport_ofi_ensure_put_counter_capacity(&ctx);
    if (before == TEST_LIMIT) {
        if (ctx.put_cntr_pending || shmem_transport_ofi_read_put_counter(&ctx))
            fatal("rebase did not reach zero\n");
        rebases++;
    }
    ctx.put_cntr_pending++;
    struct iovec local = { .iov_base = source + block * bytes,
                          .iov_len = terminal ? 0 : bytes };
    void *descriptor = fi_mr_desc(source_mr);
    struct fi_rma_iov remote = {
        .addr = peer_address + block * bytes,
        .len = local.iov_len, .key = peer_key
    };
    struct fi_msg_rma message = {
        .msg_iov = &local, .desc = &descriptor, .iov_count = 1,
        .addr = peer, .rma_iov = &remote, .rma_iov_count = 1
    };
    uint64_t flags = FI_DELIVERY_COMPLETE;
    if (terminal) flags |= FI_FENCE | FI_COMPLETION;
    ssize_t result;
    do {
        result = fi_writemsg(ep, &message, flags);
        if (result == -FI_EAGAIN)
            shmem_transport_ofi_progress_put_counter(&ctx);
    } while (result == -FI_EAGAIN);
    check((int) result, "fi_writemsg (must accept the fault asynchronously)");
}

static unsigned char pattern(unsigned int epoch, unsigned int block)
{
    return (unsigned char) (1 + ((epoch * BLOCKS + block) % 253));
}

static void run_rebase(void)
{
    for (unsigned int epoch = 0; epoch < EPOCHS; epoch++) {
        if (rank == 0) {
            for (unsigned int block = 0; block < BLOCKS; block++) {
                memset(source + block * bytes, pattern(epoch, block), bytes);
                post(block, false);
            }
            post(0, true); /* SOS-style counted, fenced terminal write. */
            shmem_transport_ofi_wait_put_counter(&ctx);
            if (shmem_transport_ofi_read_put_counter(&ctx) != ctx.put_cntr_pending)
                fatal("completion threshold differs after quiet\n");
            memset(source, 0xfe, buffer_size); /* Reuse only after delivery. */
            send_token(10);
            receive_token(11);
        } else {
            receive_token(10);
            for (unsigned int block = 0; block < BLOCKS; block++)
                for (size_t offset = 0; offset < bytes; offset++)
                    if (target[block * bytes + offset] != pattern(epoch, block))
                        fatal("payload mismatch: epoch=%u block=%u offset=%zu\n",
                              epoch, block, offset);
            send_token(11);
        }
    }
    if (rank == 0) {
        unsigned int writes = EPOCHS * (BLOCKS + 1);
        if (rebases != (writes - 1) / TEST_LIMIT)
            fatal("unexpected rebase count: %u\n", rebases);
        printf("PASS rebase bytes=%zu epochs=%d writes=%u rebases=%u"
               " receiver_payload_checks=%d\n",
               bytes, EPOCHS, writes, rebases, EPOCHS * BLOCKS);
    }
}

static void run_error(bool preexisting)
{
    /* Establish working delivery and verify bytes before injecting a fault,
     * so setup/authentication failures cannot qualify the error test. */
    if (rank == 0) {
        memset(source, 0xa5, bytes);
        post(0, false);
        shmem_transport_ofi_wait_put_counter(&ctx);
        send_token(18);
        receive_token(19);
        puts("healthy baseline delivery and receiver payload check completed");
        fflush(stdout);
    } else {
        receive_token(18);
        for (size_t offset = 0; offset < bytes; offset++)
            if (target[offset] != 0xa5)
                fatal("error-test baseline payload mismatch: %zu\n", offset);
        send_token(19);
    }
    if (rank == 1) {
        /* Revoke exactly the exchanged key: no guessed invalid key, and no
         * newly registered MR that could reuse it. This is a real RMA fault. */
        if (!preexisting) {
            check(fi_close(&target_mr->fid), "revoke remote MR");
            target_mr = NULL;
        }
        send_token(20);
        receive_token(21);
        return;
    }
    receive_token(20);
    if (preexisting) {
        check(fi_cntr_adderr(ctx.put_cntr, 1), "fi_cntr_adderr");
        while (!fi_cntr_readerr(ctx.put_cntr))
            shmem_transport_ofi_progress_put_counter(&ctx);
        ctx.put_cntr_pending++; /* Unreachable success threshold. */
        puts("preexisting hardware counter error observed before wait");
    } else {
        memset(source, 0xa5, bytes);
        post(0, false);
        puts("revoked-key write accepted; entering delivery wait");
    }
    fflush(stdout);
    catch_failure = true;
    if (setjmp(expected_failure) == 0) {
        shmem_transport_ofi_wait_put_counter(&ctx);
        catch_failure = false;
        fatal("wait returned despite injected failure\n");
    }
    catch_failure = false;
    uint64_t errors = fi_cntr_readerr(ctx.put_cntr);
    if (preexisting ? !errors : (!errors && !cq_errors))
        fatal("helper failed without hardware error evidence\n");
    printf("PASS %s counter_errors=%"PRIu64" cq_errors=%u\n",
           preexisting ? "preexisting-error" : "delivery-error", errors, cq_errors);
    fflush(stdout);
    send_token(21);
}

static void cleanup(void)
{
    if (source_mr) check(fi_close(&source_mr->fid), "close source MR");
    if (target_mr) check(fi_close(&target_mr->fid), "close target MR");
    check(fi_close(&ep->fid), "close endpoint");
    check(fi_close(&ctx.put_cntr->fid), "close counter");
    check(fi_close(&ctx.cq->fid), "close CQ");
    check(fi_close(&av->fid), "close AV");
    check(fi_close(&domain->fid), "close domain");
    check(fi_close(&fabric->fid), "close fabric");
    fi_freeinfo(info);
    free(source);
    free(target);
}

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    int ranks;
    MPI_Comm_size(MPI_COMM_WORLD, &ranks);
    if (ranks != 2 || argc != 3 ||
        (strcmp(argv[1], "rebase") && strcmp(argv[1], "preexisting-error") &&
         strcmp(argv[1], "delivery-error")))
        fatal("usage: ofi_counter_hardware rebase|preexisting-error|delivery-error"
              " BYTES (exactly two ranks on distinct hosts)\n");
    char *end;
    unsigned long parsed = strtoul(argv[2], &end, 10);
    if (!argv[2][0] || *end || parsed < 1 || parsed > 8192)
        fatal("BYTES must be an integer in 1-8192\n");
    bytes = parsed;
    buffer_size = BLOCKS * bytes;
    char local_host[MPI_MAX_PROCESSOR_NAME] = {0};
    char remote_host[MPI_MAX_PROCESSOR_NAME] = {0};
    int host_length;
    MPI_Get_processor_name(local_host, &host_length);
    MPI_Sendrecv(local_host, sizeof(local_host), MPI_BYTE, 1 - rank, 3,
                 remote_host, sizeof(remote_host), MPI_BYTE, 1 - rank, 3,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    if (!strcmp(local_host, remote_host))
        fatal("test requires distinct hosts; both ranks are on %s\n", local_host);
    printf("rank=%d host=%s peer_host=%s\n", rank, local_host, remote_host);
    fflush(stdout);
    setup();
    if (!strcmp(argv[1], "rebase")) run_rebase();
    else run_error(!strcmp(argv[1], "preexisting-error"));
    cleanup();
    MPI_Finalize();
    return 0;
}
