/* Node-local admission only. Buffer ownership and delivery tracking remain
 * private to each PE. A guaranteed quota avoids waiting on an idle peer. */
#ifndef TRANSPORT_OFI_NODE_BUDGET_H
#define TRANSPORT_OFI_NODE_BUDGET_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    uint64_t *available;
    size_t guarantee, maximum, capacity, peak_capacity;
    uint64_t leases, misses, borrowed, returned;
} shmem_transport_ofi_node_quota_t;

static inline bool
shmem_transport_ofi_node_valid(size_t pes, size_t chunk, size_t maximum,
                              size_t budget)
{
    return pes && chunk && chunk <= maximum && maximum <= SIZE_MAX / pes &&
           budget >= pes * chunk && budget <= pes * maximum;
}

static inline void
shmem_transport_ofi_node_attach(shmem_transport_ofi_node_quota_t *q,
                               uint64_t *available, size_t chunk, size_t maximum)
{
    memset(q, 0, sizeof(*q));
    q->available = available;
    q->guarantee = q->capacity = q->peak_capacity = chunk;
    q->maximum = maximum;
}

/* Caller serializes its own state. Bounded CAS contention always falls back
 * to completing its own buffers, never to waiting for another PE's credits. */
static inline bool
shmem_transport_ofi_node_admit(shmem_transport_ofi_node_quota_t *q, size_t used)
{
    if (!q->available || used < q->capacity) return true;
    if (q->capacity == q->maximum) return false;
    uint64_t available = __atomic_load_n(q->available, __ATOMIC_ACQUIRE);
    for (int tries = 0; available && tries < 32; tries++) {
        size_t grant = q->maximum - q->capacity;
        if (grant > q->guarantee) grant = q->guarantee;
        if (grant > available) grant = (size_t)available;
        if (__atomic_compare_exchange_n(q->available, &available,
                available - grant, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            q->capacity += grant;
            if (q->capacity > q->peak_capacity) q->peak_capacity = q->capacity;
            q->leases++;
            q->borrowed += grant;
            return true;
        }
    }
    q->misses++;
    return false;
}

/* Call only after actual source reclamation. Never return occupied slots.
 * Partial loans return in full when usage drops to the private guarantee. */
static inline void
shmem_transport_ofi_node_release(shmem_transport_ofi_node_quota_t *q, size_t used)
{
    if (!q->available || q->capacity <= q->guarantee) return;
    size_t returned = used <= q->guarantee ? q->capacity - q->guarantee :
        (q->capacity - used) / q->guarantee * q->guarantee;
    if (!returned) return;
    q->capacity -= returned;
    q->returned += returned;
    __atomic_fetch_add(q->available, returned, __ATOMIC_RELEASE);
}
#endif
