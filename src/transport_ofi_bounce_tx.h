/* -*- C -*- */
#ifndef TRANSPORT_OFI_BOUNCE_TX_H
#define TRANSPORT_OFI_BOUNCE_TX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SHMEM_OFI_PUT_EPOCH_DIRTY 0x01
#define SHMEM_OFI_PUT_EPOCH_WEAK  0x02

static inline bool
shmem_transport_ofi_bounce_tx_eligible(bool enabled, size_t len,
                                      size_t inject, size_t bounce,
                                      size_t max_msg)
{
    return enabled && len > 1024 && len <= 8192 && len > inject &&
           len <= bounce && len <= max_msg;
}

/* Called only after an accepted weak post, under the context lock.  CQ source
 * retirement and fabric-counter rebasing never modify this peer obligation. */
static inline void
shmem_transport_ofi_bounce_tx_mark_peer(unsigned char *dirty, int *peers,
                                       size_t *npeers, uint64_t *weak_pending,
                                       int pe)
{
    if (!(dirty[pe] & SHMEM_OFI_PUT_EPOCH_DIRTY))
        peers[(*npeers)++] = pe;
    if (!(dirty[pe] & SHMEM_OFI_PUT_EPOCH_WEAK))
        (*weak_pending)++;
    dirty[pe] |= SHMEM_OFI_PUT_EPOCH_DIRTY | SHMEM_OFI_PUT_EPOCH_WEAK;
}

#endif
