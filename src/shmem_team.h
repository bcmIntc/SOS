/* -*- C -*-
 *
 * Copyright (c) 2019 Intel Corporation. All rights reserved.
 * This software is available to you under the BSD license.
 *
 * This file is part of the Sandia OpenSHMEM software package. For license
 * information, see the LICENSE file in the top level directory of the
 * distribution.
 *
 */

#ifndef SHMEM_TEAM_H
#define SHMEM_TEAM_H

#include "transport.h"
#include "uthash.h"

#define N_PSYNCS_PER_TEAM   2

// bman: hierarchical PSYNC
#define SHMEM_MAX_RADIX 4
typedef struct 
{
    int radix;						// 4 by default
    int parent;						// -1 for root, else parent rank in team
    int children[SHMEM_MAX_RADIX];	// up to radix child ranks, -1 for none
    int num_children;

    // Hierarchical PSYNC
    long *ps_up;				// length = radix (per-parent, child->parent signals)
    long *ps_dn;				// length = radix (parent->child signals)  (optional; you can reuse ps_up with phases)
    size_t ps_stride;			// bytes between slots (>= cache line)
} shmem_internal_tree_node_t;

typedef struct 
{
    // one per PE in the team:
    shmem_internal_tree_node_t node;

    // global pool bookkeeping
    long *   ps_pool_base;		// symmetric base for this team
    size_t   ps_pool_bytes;
    uint64_t ps_epoch;			// toggled every op to avoid clears

    // map pSync pointer -> instance id (for concurrent collectives)
    // (optional) lockless hash or small fixed registry
} shmem_internal_tree_meta_t;

// /bman

struct shmem_internal_team_t {
    int                            my_pe;
    int                            start, stride, size;
    int                            psync_idx;
    int                            psync_avail[N_PSYNCS_PER_TEAM];
    shmem_team_config_t            config;
    long                           config_mask;
    size_t                         contexts_len;
    struct shmem_transport_ctx_t **contexts;

	// Hierarchical PSYNC
	shmem_internal_tree_meta_t hierarchical_psync_metaData;
	shmem_internal_tree_node_t hierarchical_psync_node;
};
typedef struct shmem_internal_team_t shmem_internal_team_t;

extern shmem_internal_team_t shmem_internal_team_world;
extern shmem_internal_team_t shmem_internal_team_shared;
extern shmem_internal_team_t shmem_internal_team_node;

enum shmem_internal_team_op_t {
    SYNC = 0,
    BCAST,
    REDUCE,
    COLLECT,
    ALLTOALL
};
typedef enum shmem_internal_team_op_t shmem_internal_team_op_t;

/* Team Management Routines */

int shmem_internal_team_init(void);

void shmem_internal_team_fini(void);

int shmem_internal_team_my_pe(shmem_internal_team_t *team);

int shmem_internal_team_n_pes(shmem_internal_team_t *team);

int shmem_internal_team_get_config(shmem_internal_team_t *team, long config_mask, shmem_team_config_t *config);

int shmem_internal_team_translate_pe(shmem_internal_team_t *src_team, int src_pe, shmem_internal_team_t *dest_team);

int shmem_internal_team_split_strided(shmem_internal_team_t *parent_team, int PE_start, int PE_stride,
                                      int PE_size, const shmem_team_config_t *config, long config_mask,
                                      shmem_internal_team_t **new_team);

int shmem_internal_team_split_2d(shmem_internal_team_t *parent_team, int xrange,
                                 const shmem_team_config_t *xaxis_config, long xaxis_mask, shmem_internal_team_t **xaxis_team,
                                 const shmem_team_config_t *yaxis_config, long yaxis_mask, shmem_internal_team_t **yaxis_team);

int shmem_internal_team_destroy(shmem_internal_team_t *team);

int shmem_internal_team_create_ctx(shmem_internal_team_t *team, long options, shmem_ctx_t *ctx);

int shmem_internal_ctx_get_team(shmem_ctx_t ctx, shmem_internal_team_t **team);

long * shmem_internal_team_choose_psync(shmem_internal_team_t *team, shmem_internal_team_op_t op);

void shmem_internal_team_release_psyncs(shmem_internal_team_t *team, shmem_internal_team_op_t op);

static inline
int shmem_internal_team_pe(shmem_internal_team_t *team, int pe)
{
    return team->start + team->stride * pe;
}

#endif
