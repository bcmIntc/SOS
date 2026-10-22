/* Test-only model: accepted writes remain queued until quiet delivers them.
 * The early-return mutation deliberately leaves that queue undelivered.
 * TCP calls cannot progress the queue. This is not a CXI provider emulator,
 * nor evidence that the real transport has passed its delayed-delivery gate.
 */
#define _POSIX_C_SOURCE 200809L
#include "shmem.h"
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define BANK_BYTES 2097152
#define HEADER_BYTES 4096
#define MAP_BYTES (HEADER_BYTES + 2 * BANK_BYTES)

struct sync_header {
    unsigned int arrivals;
    unsigned int generation;
};

struct write_op {
    void *target;
    const void *source;
    void *owned_source;
    size_t bytes;
    struct write_op *next;
};

static unsigned char *mapping, *bank;
static struct sync_header *sync_header;
static struct write_op *head, **tail = &head;
static size_t allocated;
static int rank, early_return;

void shmem_global_exit(int status)
{
    fflush(NULL);
    _Exit(status);
}

static void die(const char *message)
{
    fprintf(stderr, "quiet model: %s\n", message);
    shmem_global_exit(1);
}

int shmem_init_thread(int requested, int *provided)
{
    const char *pe = getenv("SOS_QUIET_MODEL_PE");
    const char *file = getenv("SOS_QUIET_MODEL_FILE");
    const char *mutation = getenv("SOS_QUIET_MODEL_EARLY_RETURN");
    if (!pe || (strcmp(pe, "0") && strcmp(pe, "1")) || !file)
        die("requires two locally launched model PEs and a backing file");
    rank = atoi(pe);
    early_return = mutation && !strcmp(mutation, "1");
    int fd = open(file, O_RDWR);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size != MAP_BYTES)
        die("invalid shared backing file");
    mapping = mmap(NULL, MAP_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (mapping == MAP_FAILED)
        die("mmap failed");
    sync_header = (struct sync_header *) mapping;
    if (!__atomic_is_lock_free(sizeof(sync_header->arrivals), &sync_header->arrivals) ||
        !__atomic_is_lock_free(sizeof(sync_header->generation), &sync_header->generation))
        die("model requires lock-free shared unsigned atomics");
    bank = mapping + HEADER_BYTES + (size_t) rank * BANK_BYTES;
    if (requested != SHMEM_THREAD_SINGLE)
        die("model supports SINGLE only");
    *provided = SHMEM_THREAD_SINGLE;
    return 0;
}

int shmem_my_pe(void) { return rank; }
int shmem_n_pes(void) { return 2; }

/* Virtual distinct hosts for testing the real oracle locally. The TCP route
 * is independently supplied as 127.0.0.1 by the model test driver. */
int gethostname(char *name, size_t len)
{
    int n = snprintf(name, len, "quiet-model-pe-%d", rank);
    return n < 0 || (size_t) n >= len ? -1 : 0;
}

void *shmem_malloc(size_t bytes)
{
    size_t offset = (allocated + 63) & ~(size_t) 63;
    if (offset > BANK_BYTES || bytes > BANK_BYTES - offset)
        die("model symmetric allocation overflow");
    allocated = offset + bytes;
    return bank + offset;
}

void shmem_free(void *ptr) { (void) ptr; }

static void *peer_pointer(const void *ptr, size_t bytes, int pe)
{
    uintptr_t address = (uintptr_t) ptr, base = (uintptr_t) bank;
    if (pe < 0 || pe > 1 || address < base || address - base > BANK_BYTES ||
        bytes > BANK_BYTES - (address - base))
        die("invalid model symmetric address");
    return mapping + HEADER_BYTES + (size_t) pe * BANK_BYTES + (address - base);
}

void shmem_getmem(void *target, const void *source, size_t bytes, int pe)
{
    memcpy(target, peer_pointer(source, bytes, pe), bytes);
}

static void post(void *target, const void *source, size_t bytes, int pe, int copy)
{
    struct write_op *op = calloc(1, sizeof(*op));
    if (!op)
        die("model write metadata allocation failed");
    op->target = peer_pointer(target, bytes, pe);
    op->bytes = bytes;
    op->source = source;
    if (copy) {
        op->owned_source = malloc(bytes);
        if (!op->owned_source)
            die("model source allocation failed");
        memcpy(op->owned_source, source, bytes);
        op->source = op->owned_source;
    }
    *tail = op;
    tail = &op->next;
}

void shmem_ctx_putmem(shmem_ctx_t ctx, void *target, const void *source,
                      size_t bytes, int pe)
{
    if (ctx != SHMEM_CTX_DEFAULT)
        die("model supports the default context only");
    post(target, source, bytes, pe, 1);
}

void shmem_putmem_nbi(void *target, const void *source, size_t bytes, int pe)
{
    post(target, source, bytes, pe, 0);
}

void shmem_quiet(void)
{
    if (early_return)
        return;
    while (head) {
        struct write_op *op = head;
        memcpy(op->target, op->source, op->bytes);
        head = op->next;
        free(op->owned_source);
        free(op);
    }
    tail = &head;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

void shmem_barrier_all(void)
{
    shmem_quiet();
    unsigned int generation = __atomic_load_n(&sync_header->generation,
                                              __ATOMIC_ACQUIRE);
    if (__atomic_fetch_add(&sync_header->arrivals, 1, __ATOMIC_ACQ_REL) == 1) {
        __atomic_store_n(&sync_header->arrivals, 0, __ATOMIC_RELAXED);
        __atomic_fetch_add(&sync_header->generation, 1, __ATOMIC_RELEASE);
    } else {
        while (__atomic_load_n(&sync_header->generation,
                                __ATOMIC_ACQUIRE) == generation)
            sched_yield();
    }
}

void shmem_finalize(void)
{
    shmem_quiet();
    munmap(mapping, MAP_BYTES);
}
