/* -*- C -*-
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S.  Government
 * retains certain rights in this software.
 *
 * Copyright (c) 2017 Intel Corporation. All rights reserved.
 * This software is available to you under the BSD license.
 *
 * This file is part of the Sandia OpenSHMEM software package. For license
 * information, see the LICENSE file in the top level directory of the
 * distribution.
 *
 */

#include "config.h"
#include <string.h>

#include "shmem.h"
#include "shmem_internal.h"
#include "shmem_collectives.h"
#include "shmem_internal_op.h"


//
// bman
//
#include "assert.h"
#define HIERARCHICAL_PSYNC
#define HIERARCHICAL_PSYNC_SIZE 128		// 128 bytes per PSYNC slot - max spread (64 is min)
#define	HIERARCHICAL_PSYNC_NUM_CHANNELS 2	// dedicated up and down syncs

/* Channels */
//#define PSYNC_UP     0       // children -> parent
//#define PSYNC_DOWN   1       // parent -> children (private per middle node, shared for leaves)
#define CHAN_UP   0   /* my_up: I (the PE) am the owner, children increment this to notify me */
#define CHAN_DOWN 1   /* my_down: I (the PE) am the owner, my parent writes here to release me */

/* Helper macro to compute psync pointer */
// !!These are only for barriers (i.e. shmem_internal_barrier_all_psync[]) - need to generalize! TODO
#define PSYNC_INDEX(pe, channel) \
    ((pe) * HIERARCHICAL_PSYNC_SIZE * HIERARCHICAL_PSYNC_NUM_CHANNELS + \
     (channel) * HIERARCHICAL_PSYNC_SIZE)

#define MY_UP(pe)    (&shmem_internal_barrier_all_psync[PSYNC_INDEX((pe), 0)])
#define MY_DOWN(pe)  (&shmem_internal_barrier_all_psync[PSYNC_INDEX((pe), 1)])

enum { PSYNC_UP = 0, PSYNC_DOWN = 1 };

#define PSYNC_ADDR(pe, chan) \
    (&shmem_internal_barrier_all_psync[((pe) * HIERARCHICAL_PSYNC_NUM_CHANNELS + (chan)) * HIERARCHICAL_PSYNC_SIZE])

static const size_t STRIDE_LONGS = (HIERARCHICAL_PSYNC_SIZE / sizeof(long));

/* helper to compute base pointer (in longs) for (pe,chan) */
static inline long *psync_base(int pe, int chan) 
{
    /* index in longs */
    size_t stride_longs = HIERARCHICAL_PSYNC_SIZE / sizeof(long);
    size_t idx = ((size_t)pe * HIERARCHICAL_PSYNC_NUM_CHANNELS + (size_t)chan) * stride_longs;
    return &shmem_internal_barrier_all_psync[idx];
}

//
// /bman
// 


coll_type_t shmem_internal_barrier_type = AUTO;
coll_type_t shmem_internal_bcast_type = AUTO;
coll_type_t shmem_internal_reduce_type = AUTO;
coll_type_t shmem_internal_collect_type = AUTO;
coll_type_t shmem_internal_fcollect_type = AUTO;
long *shmem_internal_barrier_all_psync;
long *shmem_internal_sync_all_psync;

char *coll_type_str[] = { "AUTO",
                          "LINEAR",
                          "TREE",
                          "DISSEM",
                          "RING",
                          "RECDBL" };

static int *full_tree_children;
static int full_tree_num_children;
static int full_tree_parent;
#if defined(HIERARCHICAL_PSYNC)
 static int parent_num_children;
#endif
static long tree_radix = -1;


static int
shmem_internal_build_kary_tree(int radix, int PE_start, int stride,
                               int PE_size, int PE_root, int *parent,
                               int *num_children, int *children)
{
    int i;

	// bman. R: not seen - using single team.
	printf("[%d] shmem_internal_build_kary_tree(): radix = %d \n", shmem_internal_my_pe, radix);

    /* my_id is the index in a theoretical 0...N-1 array of
       participating tasks. where the 0th entry is the root */
    int my_id = (((shmem_internal_my_pe - PE_start) / stride) + PE_size - PE_root) % PE_size;

    /* We shift PE_root to index 0, resulting in a PE active set layout of (for
       example radix 2): 0 [ 1 2 ] [ 3 4 ] [ 5 6 ] ...  The first group [ 1 2 ]
       are chilren of 0, second group [ 3 4 ] are chilren of 1, and so on */
    *parent = PE_start + (((my_id - 1) / radix + PE_root) % PE_size) * stride;

    *num_children = 0;
    for (i = 1 ; i <= radix ; ++i) {
        int tmp = radix * my_id + i;
        if (tmp < PE_size) {
            const int child_idx = (PE_root + tmp) % PE_size;
            children[(*num_children)++] = PE_start + child_idx * stride;
        }
    }

    if (shmem_internal_params.DEBUG) {
        size_t len;
        char debug_str[256];
        len = snprintf(debug_str, sizeof(debug_str), "Building k-ary tree:"
                       "\n\t\tradix=%d, PE_start=%d, stride=%d, PE_size=%d, PE_root=%d\n",
                       radix, PE_start, stride, PE_size, PE_root);

        len += snprintf(debug_str+len, sizeof(debug_str) - len, "\t\tid=%d, parent=%d, children[%d] = { ",
                        my_id, *parent, *num_children);

        for (i = 0; i < *num_children && len < sizeof(debug_str); i++)
            len += snprintf(debug_str+len, sizeof(debug_str) - len, "%d ",
                            children[i]);

        if (len < sizeof(debug_str))
            len += snprintf(debug_str+len, sizeof(debug_str) - len, "}");

        DEBUG_STR(debug_str);
    }

    return 0;
}


/* Circulator iterator for PE active sets */
static inline int
shmem_internal_circular_iter_next(int curr, int PE_start, int PE_stride, int PE_size)
{
    const int last = PE_start + (PE_stride * (PE_size - 1));
    int next;

    next = curr + PE_stride;
    if (next > last)
        next = PE_start;

    return next;
}


int
shmem_internal_collectives_init(void)
{
    int i, j, k;
    int tmp_radix;
    int my_root = 0;
    char *type;

    tree_radix = shmem_internal_params.COLL_RADIX;	// tree_radix = 4

    /* initialize barrier_all psync array */
#if defined(HIERARCHICAL_PSYNC)
	// Allocate an array of pointers to hold counters for all internal nodes with cache-friendly offsets between elements
	assert(HIERARCHICAL_PSYNC_SIZE % sizeof(long) == 0);
	size_t total_longs = shmem_internal_num_pes * HIERARCHICAL_PSYNC_NUM_CHANNELS * STRIDE_LONGS;
	
	shmem_internal_barrier_all_psync = shmem_internal_shmalloc(total_longs * sizeof(long));	// TODO: ensure we only use this for on-node!
    if (NULL == shmem_internal_barrier_all_psync) return -1;

	for (int i = 0; i < total_longs; i++)
        shmem_internal_barrier_all_psync[i] = SHMEM_SYNC_VALUE;

#else

    shmem_internal_barrier_all_psync = shmem_internal_shmalloc(sizeof(long) * SHMEM_BARRIER_SYNC_SIZE); // SHMEM_BARRIER_SYNC_SIZE = 16
    if (NULL == shmem_internal_barrier_all_psync) return -1;
    for (i = 0; i < SHMEM_BARRIER_SYNC_SIZE; i++)
        shmem_internal_barrier_all_psync[i] = SHMEM_SYNC_VALUE;
#endif

	printf("==> [%d] shmem_internal_collectives_init(): Allocating shmem_internal_barrier_all_psync at %p. SHMEM_BARRIER_SYNC_SIZE = %d, tree_radix = %ld \n", 
																				shmem_internal_my_pe, shmem_internal_barrier_all_psync, SHMEM_BARRIER_SYNC_SIZE, tree_radix);

    /* initialize sync_all psync array */
    shmem_internal_sync_all_psync = shmem_internal_shmalloc(sizeof(long) * SHMEM_BARRIER_SYNC_SIZE);
    if (NULL == shmem_internal_sync_all_psync) return -1;
	//printf("==> [%d] shmem_internal_collectives_init(): Allocating shmem_internal_sync_all_psync at %p \n", shmem_internal_my_pe, shmem_internal_sync_all_psync);
    for (i = 0; i < SHMEM_BARRIER_SYNC_SIZE; i++)
        shmem_internal_sync_all_psync[i] = SHMEM_SYNC_VALUE;


    /* initialize the radix-k spanning tree for collective operations over all PEs */
	// Dev Note: Counts how many direct children this PE will have.
    full_tree_num_children = 0;
    for (i = 1 ; i <= shmem_internal_num_pes ; i *= tree_radix) 
	{
        tmp_radix = (shmem_internal_num_pes / i < tree_radix) ? (shmem_internal_num_pes / i) + 1 : tree_radix;
        my_root = (shmem_internal_my_pe / (tmp_radix * i)) * (tmp_radix * i);
        if (my_root != shmem_internal_my_pe) break;
        for (j = 1 ; j < tmp_radix ; ++j) 
		{
            if (shmem_internal_my_pe + i * j < shmem_internal_num_pes) 
			{
                full_tree_num_children++;
            }
        }
    }

	// Store the children: Now you have the actual child list in full_tree_children[].
    full_tree_children = malloc(sizeof(int) * full_tree_num_children);
    if (NULL == full_tree_children) return -1;

    k = full_tree_num_children - 1;
    for (i = 1 ; i <= shmem_internal_num_pes ; i *= tree_radix)
	{
        tmp_radix = (shmem_internal_num_pes / i < tree_radix) ? (shmem_internal_num_pes / i) + 1 : tree_radix;
        my_root = (shmem_internal_my_pe / (tmp_radix * i)) * (tmp_radix * i);
        if (my_root != shmem_internal_my_pe) break;
        for (j = 1 ; j < tmp_radix ; ++j)
		{
            if (shmem_internal_my_pe + i * j < shmem_internal_num_pes)
			{
                full_tree_children[k--] = shmem_internal_my_pe + i * j;		// store the child in the tree
            }
        }
    }
    full_tree_parent = my_root;												// set the root of the tree to me. Each PE owns its own view of the tree.

#if defined(HIERARCHICAL_PSYNC)
	// TODO: Remove if not needed (parent_num_children)
	parent_num_children = 0;
	for (i = 1 ; i <= shmem_internal_num_pes ; i *= tree_radix) 
	{
	    tmp_radix = (shmem_internal_num_pes / i < tree_radix) ? (shmem_internal_num_pes / i) + 1 : tree_radix;
		my_root = (full_tree_parent / (tmp_radix * i)) * (tmp_radix * i);
	    if (my_root != full_tree_parent) break;
	    for (j = 1 ; j < tmp_radix ; ++j) {
	        if (full_tree_parent + i * j < shmem_internal_num_pes) {
	            parent_num_children++;
	        }
	    }
	}
	// bman
	printf("==> [%d] shmem_internal_collectives_init(): full_tree_num_children=%d, full_tree_parent=%d, parent_num_children = %d \n", 
													shmem_internal_my_pe, full_tree_num_children, full_tree_parent, parent_num_children);
#endif


    if (shmem_internal_params.BARRIER_ALGORITHM_provided) {
        type = shmem_internal_params.BARRIER_ALGORITHM;
        if (0 == strcmp(type, "auto")) {
            shmem_internal_barrier_type = AUTO;
        } else if (0 == strcmp(type, "linear")) {
            shmem_internal_barrier_type = LINEAR;
        } else if (0 == strcmp(type, "tree")) {
            shmem_internal_barrier_type = TREE;
        } else if (0 == strcmp(type, "dissem")) {
            shmem_internal_barrier_type = DISSEM;
        } else {
            RAISE_WARN_MSG("Ignoring bad barrier algorithm '%s'\n", type);
        }
    }
    if (shmem_internal_params.BCAST_ALGORITHM_provided) {
        type = shmem_internal_params.BCAST_ALGORITHM;
        if (0 == strcmp(type, "auto")) {
            shmem_internal_bcast_type = AUTO;
        } else if (0 == strcmp(type, "linear")) {
            shmem_internal_bcast_type = LINEAR;
        } else if (0 == strcmp(type, "tree")) {
            shmem_internal_bcast_type = TREE;
        } else {
            RAISE_WARN_MSG("Ignoring bad broadcast algorithm '%s'\n", type);
        }
    }
    if (shmem_internal_params.REDUCE_ALGORITHM_provided) {
        type = shmem_internal_params.REDUCE_ALGORITHM;
        if (0 == strcmp(type, "auto")) {
            shmem_internal_reduce_type = AUTO;
        } else if (0 == strcmp(type, "linear")) {
            shmem_internal_reduce_type = LINEAR;
        } else if (0 == strcmp(type, "ring")) {
            shmem_internal_reduce_type = RING;
        } else if (0 == strcmp(type, "tree")) {
            shmem_internal_reduce_type = TREE;
        } else if (0 == strcmp(type, "recdbl")) {
            shmem_internal_reduce_type = RECDBL;
        } else {
            RAISE_WARN_MSG("Ignoring bad reduction algorithm '%s'\n", type);
        }
    }
    if (shmem_internal_params.COLLECT_ALGORITHM_provided) {
        type = shmem_internal_params.COLLECT_ALGORITHM;
        if (0 == strcmp(type, "auto")) {
            shmem_internal_collect_type = AUTO;
        } else if (0 == strcmp(type, "linear")) {
            shmem_internal_collect_type = LINEAR;
        } else {
            RAISE_WARN_MSG("Ignoring bad collect algorithm '%s'\n", type);
        }
    }
    if (shmem_internal_params.FCOLLECT_ALGORITHM_provided) {
        type = shmem_internal_params.FCOLLECT_ALGORITHM;
        if (0 == strcmp(type, "auto")) {
            shmem_internal_fcollect_type = AUTO;
        } else if (0 == strcmp(type, "linear")) {
            shmem_internal_fcollect_type = LINEAR;
        } else if (0 == strcmp(type, "tree")) {
            shmem_internal_fcollect_type = TREE;
        } else if (0 == strcmp(type, "ring")) {
            shmem_internal_fcollect_type = RING;
        } else if (0 == strcmp(type, "recdbl")) {
            shmem_internal_fcollect_type = RECDBL;
        } else {
            RAISE_WARN_MSG("Ignoring bad fcollect algorithm '%s'\n", type);
        }
    }

    return 0;
}


/*****************************************
 *
 * BARRIER/SYNC Implementations
 *
 *****************************************/
void
shmem_internal_sync_linear(int PE_start, int PE_stride, int PE_size, long *pSync)
{
    long zero = 0, one = 1;

	// bman
	printf("==> [%d] shmem_internal_sync_linear(): &pSync = %p \n", shmem_internal_my_pe, pSync);

    /* need 1 slot */
    shmem_internal_assert(SHMEM_BARRIER_SYNC_SIZE >= 1);

    if (PE_start == shmem_internal_my_pe) {
        int pe, i;

        /* wait for N - 1 callins up the tree */
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, PE_size - 1);

        /* Clear pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero),
                                 shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);

        /* Send acks down psync tree */
        for (pe = PE_start + PE_stride, i = 1 ;
             i < PE_size ;
             i++, pe += PE_stride) {
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one), pe);
        }

    } else {
        /* send message to root */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one), PE_start,
                              SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* wait for ack down psync tree */
        SHMEM_WAIT(pSync, 0);

        /* Clear pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero),
                                 shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);
    }

}


// bman
//static inline long *UP_SLOT(int pe)   { return &shmem_internal_barrier_all_psync[(pe * HIERARCHICAL_PSYNC_NUM_CHANNELS + CHAN_UP) * STRIDE_LONGS]; }
//static inline long *DOWN_SLOT(int pe) { return &shmem_internal_barrier_all_psync[(pe * HIERARCHICAL_PSYNC_NUM_CHANNELS + CHAN_DOWN) * STRIDE_LONGS]; }
#define UP_SLOT(x)   ((x))           // Slot children increment to signal parent
#define DOWN_SLOT(x) ((x) + 1)     // Slot parent writes to signal children

void shmem_internal_sync_tree(int PE_start, int PE_stride, int PE_size, long *pSync)
{
    long zero = 0, one = 1, *myPsync = pSync;
    int parent, num_children, *children;
	// new
	long *my_up, *my_down;   // local pointers to own up/down slots

    /* need 1 slot */
    shmem_internal_assert(SHMEM_BARRIER_SYNC_SIZE >= 1);

    if (PE_size == shmem_internal_num_pes) 
	{
        /* we're the full tree, use the binomial (except its not) tree */
        parent		 = full_tree_parent;
        num_children = full_tree_num_children;
        children	 = full_tree_children;
		// bman
		printf("==> [%d] +shmem_internal_sync_tree: Full Tree: parent=%d, num_children=%d, shmem_internal_num_pes=%d \n", 
																shmem_internal_my_pe, parent, num_children, shmem_internal_num_pes); fflush(stdout);
    } 
	else 
	{
		//  TODO: port for this also (non-full tree). Currently assuming above case only!
		assert(0);

        children = alloca(sizeof(int) * tree_radix);
        shmem_internal_build_kary_tree(tree_radix, PE_start, PE_stride, PE_size, 0, &parent, &num_children, children);
    }

#if 1
	/* Setup my slots */
	my_up   = &shmem_internal_barrier_all_psync[shmem_internal_my_pe * STRIDE_LONGS];       // slot for children to increment
	my_down = &shmem_internal_barrier_all_psync[shmem_internal_my_pe * STRIDE_LONGS + 1];   // slot to wait for parent release

    if (num_children != 0)
    {
        /* Not a pure leaf node */
        int i;

	    // Wait for all children to signal
	    SHMEM_WAIT_UNTIL(UP_SLOT(my_up), SHMEM_CMP_EQ, num_children);

        if (parent == shmem_internal_my_pe)
        {
            /* The root of the tree */

		  #if 0
			/* Wait on our childrens */
            myPsync = &shmem_internal_barrier_all_psync[parent * STRIDE_LONGS];   // NOTE: PE[0]'s parent is 0.
            printf("\t[%d] Root: Wait for Children... (num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, num_children);

            /* Clear pSync */
            printf("\t[%d] Root: Clearing my PSYNC... (num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &zero, sizeof(zero), shmem_internal_my_pe);  // selfing
            printf("\t[%d] Root: Wait for that to sink... \n", shmem_internal_my_pe);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, 0);

            /* Send acks down to children */
            printf("\t[%d] Root: ACk children... (num_children=%d, myPsync=%p) \n", shmem_internal_my_pe, num_children, myPsync);
            for (i = 0 ; i < num_children ; ++i) {
                //shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), children[i], SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
				shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &num_children, sizeof(num_children), children[i]);	// bman: change to update each child with total #children
            }
		  #else

	        // Clear my slots
		    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, UP_SLOT(my_up), &zero, sizeof(zero), shmem_internal_my_pe);
			shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, DOWN_SLOT(my_down), &zero, sizeof(zero), shmem_internal_my_pe);

	        // Release children
		    for (i = 0; i < num_children; ++i) {
			    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, DOWN_SLOT(&shmem_internal_barrier_all_psync[children[i] * STRIDE_LONGS + 1]), &one, sizeof(one), children[i]);
	        }
		  #endif
            printf("\t[%d] Root: DONE*\n", shmem_internal_my_pe);

        }
        else
        {
            /* Middle of the tree */

		  #if 0
			/* Wait on our childrens */
            myPsync = &shmem_internal_barrier_all_psync[shmem_internal_my_pe * STRIDE_LONGS];     // update PSYNC to the one we share with our childrens
            printf("\t[%d] Mid: Wait for Children... (num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, num_children);                          // now wait for our kids to up-sync

            myPsync = &shmem_internal_barrier_all_psync[parent * STRIDE_LONGS];                   // now switch PSYNC to the one we share with our parent
            printf("\t[%d] Mid: Children reported up, switching PSYNC to parent (num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);

            /* send ack to parent  - we may need a dedicated channel since the root can have pure leaf children also! TODO */
            printf("\t[%d] Mid: ACK parent... (num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
            shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

            /* wait for ack from parent */
            printf("\t[%d] Mid: Wait for Parent (parent # children waiting on = %d)\n", shmem_internal_my_pe, parent_num_children);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, parent_num_children);		// NOTE: this only works if the Root broadcasts its results, which it should.
            // we do not have a shared psync -- Wait on how many children our parent has, including us.         <<== STUCK HERE

            /* Clear my pSync */
            printf("\t[%d] Mid: Clearing my PSYNC...\n", shmem_internal_my_pe);
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &zero, sizeof(zero), shmem_internal_my_pe);
            printf("\t[%d] Mid: Waiting for that to sink...\n", shmem_internal_my_pe);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, 0);

            /* Send acks down to children */
            myPsync = &shmem_internal_barrier_all_psync[shmem_internal_my_pe * STRIDE_LONGS];     // update psync domain
            printf("\t[%d] Mid: ACK children... (updated myPsync=%p)\n", shmem_internal_my_pe, myPsync);
            for (i = 0 ; i < num_children ; ++i) 
			{
                //shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), children[i], SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
				shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &num_children, sizeof(num_children), children[i]);	// bman: change to update each child with total #children
            }
		  #else

	        // Notify parent
		    shmem_internal_atomic(SHMEM_CTX_DEFAULT, UP_SLOT(&shmem_internal_barrier_all_psync[parent * STRIDE_LONGS]), &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

	        // Wait for parent release
		    SHMEM_WAIT_UNTIL(DOWN_SLOT(my_down), SHMEM_CMP_EQ, 1);

			// Clear own slots
	        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, UP_SLOT(my_up), &zero, sizeof(zero), shmem_internal_my_pe);
		    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, DOWN_SLOT(my_down), &zero, sizeof(zero), shmem_internal_my_pe);

			// Release children
	        for (i = 0; i < num_children; ++i) {
		        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, DOWN_SLOT(&shmem_internal_barrier_all_psync[children[i] * STRIDE_LONGS + 1]), &one, sizeof(one), children[i]);
	        }
		  #endif

            printf("\t[%d] Mid: DONE*\n", shmem_internal_my_pe);
        }

    }
    else
    {
        /* Pure leaf node */

	  #if 0
        myPsync = &shmem_internal_barrier_all_psync[parent * STRIDE_LONGS];

        /* send message up psync tree */
        printf("\t[%d] Leaf: ACK parent... (num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* wait for ack down psync tree */
        printf("\t[%d] Leaf: Wait for parent... (parent # children waiting on = %d) \n", shmem_internal_my_pe, parent_num_children);
        //SHMEM_WAIT(myPsync, 0);	// NOTE: this API is poorly named - this waits for !0. Is that enough? Or should it wait for the correct #?
		SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, parent_num_children);

        /* Clear my pSync */
        printf("\t[%d] Leaf: Clearing my PSYNC...\n", shmem_internal_my_pe);
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &zero, sizeof(zero), shmem_internal_my_pe);
        printf("\t[%d] Leaf: Waiting for that to sink... \n", shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, 0);
	  #else
	    // Notify parent
	    shmem_internal_atomic(SHMEM_CTX_DEFAULT, UP_SLOT(&shmem_internal_barrier_all_psync[parent * STRIDE_LONGS]), &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

	    // Wait for parent release
		SHMEM_WAIT_UNTIL(DOWN_SLOT(my_down), SHMEM_CMP_EQ, 1);

	    // Clear own slots
		shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, UP_SLOT(my_up), &zero, sizeof(zero), shmem_internal_my_pe);
	    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, DOWN_SLOT(my_down), &zero, sizeof(zero), shmem_internal_my_pe);
	  #endif

        printf("\t[%d] Leaf: DONE*\n", shmem_internal_my_pe);
    }
#endif // OG - adapted

#if 0

 #if 1
 {
    // !!DIAG!!
	/* compute pointers we expect to use */
	long *my_up    = psync_base(shmem_internal_my_pe, 0); /* up channel owned by me */
	long *my_down  = psync_base(shmem_internal_my_pe, 1); /* down channel owned by me */
	long *parent_up = (parent >= 0) ? psync_base(parent, 0) : NULL;
	long *parent_down = (parent >= 0) ? psync_base(parent, 1) : NULL;

	/* print diagnostics (one-line per PE) */
	printf("[DIAG] PE %2d: my_up=%p my_down=%p parent=%d parent_up=%p parent_down=%p\n", shmem_internal_my_pe, (void*)my_up, (void*)my_down, parent, (void*)parent_up, (void*)parent_down);
	fflush(stdout);

	/* Also print initial values of the first long at those locations */
	long read_my_up = my_up[0];
	long read_my_down = my_down[0];
	long read_parent_up = parent_up ? parent_up[0] : -1;
	long read_parent_down = parent_down ? parent_down[0] : -1;

	printf("[DIAG] PE %2d initial vals: my_up=%ld my_down=%ld parent_up=%ld parent_down=%ld\n",
       shmem_internal_my_pe, read_my_up, read_my_down, read_parent_up, read_parent_down);
	fflush(stdout);
  }
  #endif

    // --- Leaf node ---
    if (num_children == 0) 
	{
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, my_up, &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
        printf("[LEAF] PE %d sent up to parent %d\n", shmem_internal_my_pe, parent);

        SHMEM_WAIT(my_down, 0);
        printf("[LEAF] PE %d released by parent\n", shmem_internal_my_pe);

        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, my_up, &zero, sizeof(zero), shmem_internal_my_pe);
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, my_down, &zero, sizeof(zero), shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(my_up, SHMEM_CMP_EQ, 0);
        SHMEM_WAIT_UNTIL(my_down, SHMEM_CMP_EQ, 0);
        return;
    }

    // --- Internal / root node ---
    printf("[NODE] PE %d waiting for %d children\n", shmem_internal_my_pe, num_children);
    SHMEM_WAIT_UNTIL(my_up, SHMEM_CMP_EQ, num_children);
    printf("[NODE] PE %d children arrived\n", shmem_internal_my_pe);

    if (parent != shmem_internal_my_pe) 
	{
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, psync_base(parent, CHAN_UP), &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
        printf("[NODE] PE %d sent up to parent %d\n", shmem_internal_my_pe, parent);

        SHMEM_WAIT_UNTIL(psync_base(shmem_internal_my_pe, CHAN_DOWN), SHMEM_CMP_EQ, parent_num_children);
        printf("[NODE] PE %d released by parent\n", shmem_internal_my_pe);
	}

#endif
#if 0
    if (num_children != 0) 
	{
        /* Not a pure leaf node */
        int i;

        /* wait for num_children callins up the tree */
	  #if defined(HIERARCHICAL_PSYNC)
		myPsync = &shmem_internal_barrier_all_psync[parent * stride];	// NOTE: root's parent is 0.
		printf("\t[%d] A(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
	  #else
        SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, num_children);
	  #endif	

        if (parent == shmem_internal_my_pe) 
		{
            /* The root of the tree */

		  #if defined(HIERARCHICAL_PSYNC)
			myPsync = &shmem_internal_barrier_all_psync[parent * stride];	// NOTE: PE[0]'s parent is 0.
			printf("\t[%d] B.0(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
			SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, num_children);
		  #endif

            /* Clear pSync */
			printf("\t[%d] B.1(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &zero, sizeof(zero), shmem_internal_my_pe);  // selfing
			printf("\t[%d] B.2\n", shmem_internal_my_pe);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, 0);

            /* Send acks down to children */
			printf("\t[%d] B.3\n", shmem_internal_my_pe);
            for (i = 0 ; i < num_children ; ++i) {
                shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), children[i], SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
            }
			printf("\t[%d] B.4*\n", shmem_internal_my_pe);

        } 
		else 
		{
            /* Middle of the tree */

		#if defined(HIERARCHICAL_PSYNC)
			myPsync = &shmem_internal_barrier_all_psync[shmem_internal_my_pe * stride];		// update PSYNC to the one we share with our childrens
			printf("\t[%d] C.0A(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
			SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, num_children);							// now wait for our kids to up-sync

			myPsync = &shmem_internal_barrier_all_psync[parent * stride];					// now switch PSYNC to the one we share with our parent
			printf("\t[%d] C.0B(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
		#endif

            /* send ack to parent */
			printf("\t[%d] C.1(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
            shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

            /* wait for ack from parent */
			printf("\t[%d] C.2 (pnc=%d)\n", shmem_internal_my_pe, parent_num_children);
		#if defined(HIERARCHICAL_PSYNC)
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, parent_num_children);	
			// we do not have a shared psync -- Wait on how many children our parent has, including us.			<<== STUCK HERE
		#else
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, num_children + 1); // shared psybc includes parent + kids that already udpated
		#endif
            /* Clear pSync */
			printf("\t[%d] C.3\n", shmem_internal_my_pe);
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &zero, sizeof(zero), shmem_internal_my_pe);
			printf("\t[%d] C.4\n", shmem_internal_my_pe);
            SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, 0);

            /* Send acks down to children */
		#if defined(HIERARCHICAL_PSYNC)
			myPsync = &shmem_internal_barrier_all_psync[shmem_internal_my_pe * stride];		// update psync domain
		#endif
			printf("\t[%d] C.5(updated myPsync=%p)\n", shmem_internal_my_pe, myPsync);
            for (i = 0 ; i < num_children ; ++i) {
                shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), children[i], SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
            }
			printf("\t[%d] C.6*\n", shmem_internal_my_pe);
        }

    } 
	else 
	{
        /* Pure leaf node */

	#if defined(HIERARCHICAL_PSYNC)
		myPsync = &shmem_internal_barrier_all_psync[parent * stride];
	#endif

        /* send message up psync tree */
		printf("\t[%d] D.1(num_children=%d, myPsync=%p)\n", shmem_internal_my_pe, num_children, myPsync);
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, myPsync, &one, sizeof(one), parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* wait for ack down psync tree */
		printf("\t[%d] D.2\n", shmem_internal_my_pe);
        SHMEM_WAIT(myPsync, 0);

        /* Clear pSync */
		printf("\t[%d] D.3\n", shmem_internal_my_pe);
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, myPsync, &zero, sizeof(zero), shmem_internal_my_pe);
		printf("\t[%d] D.4\n", shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(myPsync, SHMEM_CMP_EQ, 0);
		printf("\t[%d] D.5*\n", shmem_internal_my_pe);
    }
#endif // OG
}


void
shmem_internal_sync_dissem(int PE_start, int PE_stride, int PE_size, long *pSync)
{
    int one = 1, neg_one = -1;
    int distance, to, i;
    int coll_rank = (shmem_internal_my_pe - PE_start) / PE_stride;
    int *pSync_ints = (int*) pSync;

    /* need log2(num_procs) int slots.  max_num_procs is
       2^(sizeof(int)*8-1)-1, so make the math a bit easier and assume
       2^(sizeof(int) * 8), which means log2(num_procs) is always less
       than sizeof(int) * 8. */
    /* Note: pSync can be treated as a byte array rather than an int array to
     * get better cache locality.  We chose int here for portability, since SUM
     * on INT is required by the SHMEM atomics API. */
    shmem_internal_assert(SHMEM_BARRIER_SYNC_SIZE >= (sizeof(int) * 8) / (sizeof(long) / sizeof(int)));

    for (i = 0, distance = 1 ; distance < PE_size ; ++i, distance <<= 1) {
        to = ((coll_rank + distance) % PE_size);
        to = PE_start + (to * PE_stride);

        shmem_internal_atomic(SHMEM_CTX_DEFAULT, &pSync_ints[i], &one, sizeof(int),
                              to, SHM_INTERNAL_SUM, SHM_INTERNAL_INT);

        SHMEM_WAIT_UNTIL(&pSync_ints[i], SHMEM_CMP_NE, 0);
        /* There's a path where the next update from a peer can get
           here before the update below, but there's no path for two
           updates to arrive before the decrement */
        shmem_internal_assert(pSync_ints[i] < 3);

        /* this slot is no longer used, so subtract off results now */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, &pSync_ints[i], &neg_one, sizeof(int),
                              shmem_internal_my_pe, SHM_INTERNAL_SUM, SHM_INTERNAL_INT);
    }

    /* Ensure local pSync decrements are done before a subsequent barrier */
    shmem_internal_quiet(SHMEM_CTX_DEFAULT);
}


/*****************************************
 *
 * BROADCAST
 *
 *****************************************/
void
shmem_internal_bcast_linear(void *target, const void *source, size_t len,
                            int PE_root, int PE_start, int PE_stride, int PE_size,
                            long *pSync, int complete)
{
    long zero = 0, one = 1;
    int real_root = PE_start + PE_root * PE_stride;
    long completion = 0;

    /* need 1 slot */
    shmem_internal_assert(SHMEM_BCAST_SYNC_SIZE >= 1);

    if (PE_size == 1 || len == 0) return;

    if (real_root == shmem_internal_my_pe) {
        int i, pe;

        /* send data to all peers */
        for (pe = PE_start,i=0; i < PE_size; pe += PE_stride, i++) {
            if (pe == shmem_internal_my_pe) continue;
            shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, source, len, pe, &completion);
        }
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);

        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        /* send completion ack to all peers */
        for (pe = PE_start,i=0; i < PE_size; pe += PE_stride, i++) {
            if (pe == shmem_internal_my_pe) continue;
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(long), pe);
        }

        if (1 == complete) {
            /* wait for acks from everyone */
            SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, PE_size - 1);

            /* Clear pSync */
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero),
                                     shmem_internal_my_pe);
            SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);
        }

    } else {
        /* wait for data arrival message */
        SHMEM_WAIT(pSync, 0);

        /* Clear pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero),
                                 shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);

        if (1 == complete) {
            /* send ack back to root */
            shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one),
                                  real_root, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
        }
    }
}


void
shmem_internal_bcast_tree(void *target, const void *source, size_t len,
                          int PE_root, int PE_start, int PE_stride, int PE_size,
                          long *pSync, int complete)
{
    long zero = 0, one = 1;
    long completion = 0;
    int parent, num_children, *children;
    const void *send_buf = source;

    /* need 1 slot */
    shmem_internal_assert(SHMEM_BCAST_SYNC_SIZE >= 1);

    if (PE_size == 1 || len == 0) return;

    if (PE_size == shmem_internal_num_pes && 0 == PE_root) {
        /* we're the full tree, use the binomial tree */
        parent = full_tree_parent;
        num_children = full_tree_num_children;
        children = full_tree_children;
    } else {
        children = alloca(sizeof(int) * tree_radix);
        shmem_internal_build_kary_tree(tree_radix, PE_start, PE_stride, PE_size,
                                       PE_root, &parent, &num_children, children);
    }

    if (0 != num_children) {
        int i;

        if (parent != shmem_internal_my_pe) {
            send_buf = target;

            /* wait for data arrival message if not the root */
            SHMEM_WAIT(pSync, 0);

            /* if complete, send ack */
            if (1 == complete) {
                shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one),
                                      parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
            }
        }

        /* send data to all leaves */
        for (i = 0 ; i < num_children ; ++i) {
            shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, send_buf, len, children[i],
                                  &completion);
        }
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);

        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        /* send completion ack to all peers */
        for (i = 0 ; i < num_children ; ++i) {
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(long),
                                     children[i]);
        }

        if (1 == complete) {
            /* wait for acks from everyone */
            SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ,
                                  num_children  +
                                  ((parent == shmem_internal_my_pe) ?
                                   0 : 1));
        }

        /* Clear pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero),
                                 shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);

    } else {
        /* wait for data arrival message */
        SHMEM_WAIT(pSync, 0);

        /* if complete, send ack */
        if (1 == complete) {
            shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one),
                                  parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
        }

        /* Clear pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero),
                                 shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);
    }
}


/*****************************************
 *
 * REDUCTION
 *
 *****************************************/
void
shmem_internal_op_to_all_linear(void *target, const void *source, size_t count, size_t type_size,
                                int PE_start, int PE_stride, int PE_size,
                                void *pWrk, long *pSync,
                                shm_internal_op_t op, shm_internal_datatype_t datatype)
{

    long zero = 0, one = 1;
    long completion = 0;

    /* need 2 slots, plus bcast */
    shmem_internal_assert(SHMEM_REDUCE_SYNC_SIZE >= 2 + SHMEM_BCAST_SYNC_SIZE);

    if (count == 0) return;

    if (PE_start == shmem_internal_my_pe) {
        int pe, i;
        /* update our target buffer with our contribution.  The put
           will flush any atomic cache value that may currently
           exist. */
        shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, source, count * type_size,
                              shmem_internal_my_pe, &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_quiet(SHMEM_CTX_DEFAULT);

        /* let everyone know that it's safe to send to us */
        for (pe = PE_start + PE_stride, i = 1 ;
             i < PE_size ;
             i++, pe += PE_stride) {
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one), pe);
        }

        /* Wait for others to acknowledge sending data */
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, PE_size - 1);

        /* reset pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero), shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);

    } else {
        /* wait for clear to send */
        SHMEM_WAIT(pSync, 0);

        /* reset pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero), shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);

        /* send data, ack, and wait for completion */
        shmem_internal_atomicv(SHMEM_CTX_DEFAULT, target, source, count * type_size,
                               PE_start, op, datatype, &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one),
                              PE_start, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
    }

    /* broadcast out */
    shmem_internal_bcast(target, target, count * type_size, 0,
                         PE_start, PE_stride, PE_size, pSync + 2, 0);
}


#define chunk_count(id_, count_, npes_) \
    (count_)/(npes_) + ((id_) < (count_) % (_npes))

void
shmem_internal_op_to_all_ring(void *target, const void *source, size_t count, size_t type_size,
                              int PE_start, int PE_stride, int PE_size,
                              void *pWrk, long *pSync,
                              shm_internal_op_t op, shm_internal_datatype_t datatype)
{
    int group_rank = (shmem_internal_my_pe - PE_start) / PE_stride;
    long zero = 0, one = 1;

    int peer = PE_start + ((group_rank + 1) % PE_size) * PE_stride;
    int free_source = 0;

    /* One slot for reduce-scatter and another for the allgather */
    shmem_internal_assert(SHMEM_REDUCE_SYNC_SIZE >= 2 + SHMEM_BARRIER_SYNC_SIZE);

    if (count == 0) return;

    if (PE_size == 1) {
        if (target != source)
            shmem_internal_copy_self(target, source, count * type_size);
        return;
    }

    /* In-place reduction: copy source data to a temporary buffer so we can use
     * the symmetric buffer to accumulate reduced data. */
    if (target == source) {
        void *tmp = malloc(count * type_size);

        if (NULL == tmp)
            RAISE_ERROR_MSG("Unable to allocate %zub temporary buffer\n", count*type_size);

        shmem_internal_copy_self(tmp, target, count * type_size);
        free_source = 1;
        source = tmp;

        shmem_internal_sync(PE_start, PE_stride, PE_size, pSync + 2);
    }

    /* Perform reduce-scatter:
     *
     * The source buffer is divided into PE_size chunks.  PEs send data to the
     * right around the ring, starting with the chunk index equal to the PE id
     * and decreasing.  For example, with 4 PEs, PE 0 sends chunks 0, 3, 2 and
     * PE 1 sends chunks 1, 0, 3.  At the end, each PE has the reduced chunk
     * corresponding to its PE id + 1.
     */
    for (int i = 0; i < PE_size - 1; i++) {
        size_t chunk_in  = (group_rank - i - 1 + PE_size) % PE_size;
        size_t chunk_out = (group_rank - i + PE_size) % PE_size;

        /* Evenly distribute extra elements across first count % PE_size chunks */
        size_t chunk_in_extra  = chunk_in  < count % PE_size;
        size_t chunk_out_extra = chunk_out < count % PE_size;
        size_t chunk_in_count  = count/PE_size + chunk_in_extra;
        size_t chunk_out_count = count/PE_size + chunk_out_extra;

        /* Account for extra elements in the displacement */
        size_t chunk_out_disp  = chunk_out_extra ?
                                 chunk_out * chunk_out_count * type_size :
                                 (chunk_out * chunk_out_count + count % PE_size) * type_size;
        size_t chunk_in_disp   = chunk_in_extra ?
                                 chunk_in * chunk_in_count * type_size :
                                 (chunk_in * chunk_in_count + count % PE_size) * type_size;

        shmem_internal_put_nbi(SHMEM_CTX_DEFAULT,
                               ((uint8_t *) target) + chunk_out_disp,
                               i == 0 ?
                                   ((uint8_t *) source) + chunk_out_disp :
                                   ((uint8_t *) target) + chunk_out_disp,
                               chunk_out_count * type_size, peer);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one),
                              peer, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* Wait for chunk */
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_GE, i+1);

        shmem_internal_reduce_local(op, datatype, chunk_in_count,
                                    ((uint8_t *) source) + chunk_in_disp,
                                    ((uint8_t *) target) + chunk_in_disp);
    }

    /* Reset reduce-scatter pSync */
    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero), shmem_internal_my_pe);
    SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);

    /* Perform all-gather:
     *
     * Initially, each PE has the reduced chunk for PE id + 1.  Forward chunks
     * around the ring until all PEs have all chunks.
     */
    for (int i = 0; i < PE_size - 1; i++) {
        size_t chunk_out = (group_rank + 1 - i + PE_size) % PE_size;
        size_t chunk_out_extra = chunk_out < count % PE_size;
        size_t chunk_out_count = count/PE_size + chunk_out_extra;
        size_t chunk_out_disp  = chunk_out_extra ?
                                 chunk_out * chunk_out_count * type_size :
                                 (chunk_out * chunk_out_count + count % PE_size) * type_size;

        shmem_internal_put_nbi(SHMEM_CTX_DEFAULT,
                               ((uint8_t *) target) + chunk_out_disp,
                               ((uint8_t *) target) + chunk_out_disp,
                               chunk_out_count * type_size, peer);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync+1, &one, sizeof(one),
                              peer, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* Wait for chunk */
        SHMEM_WAIT_UNTIL(pSync+1, SHMEM_CMP_GE, i+1);
    }

    /* reset pSync */
    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync+1, &zero, sizeof(zero), shmem_internal_my_pe);
    SHMEM_WAIT_UNTIL(pSync+1, SHMEM_CMP_EQ, 0);

    if (free_source)
        free((void *)source);
}


void
shmem_internal_op_to_all_tree(void *target, const void *source, size_t count, size_t type_size,
                              int PE_start, int PE_stride, int PE_size,
                              void *pWrk, long *pSync,
                              shm_internal_op_t op, shm_internal_datatype_t datatype)
{
    long zero = 0, one = 1;
    long completion = 0;
    int parent, num_children, *children;

    /* need 2 slots, plus bcast */
    shmem_internal_assert(SHMEM_REDUCE_SYNC_SIZE >= 2 + SHMEM_BCAST_SYNC_SIZE);

    if (PE_size == 1) {
        if (target != source) {
            shmem_internal_copy_self(target, source, type_size * count);
        }
        return;
    }

    if (count == 0) return;

    if (PE_size == shmem_internal_num_pes) {
        /* we're the full tree, use the binomial tree */
        parent = full_tree_parent;
        num_children = full_tree_num_children;
        children = full_tree_children;
    } else {
        children = alloca(sizeof(int) * tree_radix);
        shmem_internal_build_kary_tree(tree_radix, PE_start, PE_stride, PE_size,
                                       0, &parent, &num_children, children);
    }

    if (0 != num_children) {
        int i;

        /* update our target buffer with our contribution.  The put
           will flush any atomic cache value that may currently
           exist. */
        shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, source, count * type_size,
                              shmem_internal_my_pe, &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_quiet(SHMEM_CTX_DEFAULT);

        /* let everyone know that it's safe to send to us */
        for (i = 0 ; i < num_children ; ++i) {
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync + 1, &one, sizeof(one), children[i]);
        }

        /* Wait for others to acknowledge sending data */
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, num_children);

        /* reset pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(zero), shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);
    }

    if (parent != shmem_internal_my_pe) {
        /* wait for clear to send */
        SHMEM_WAIT(pSync + 1, 0);

        /* reset pSync */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync + 1, &zero, sizeof(zero), shmem_internal_my_pe);
        SHMEM_WAIT_UNTIL(pSync + 1, SHMEM_CMP_EQ, 0);

        /* send data, ack, and wait for completion */
        shmem_internal_atomicv(SHMEM_CTX_DEFAULT, target,
                               (num_children == 0) ? source : target,
                               count * type_size, parent,
                               op, datatype, &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(one),
                              parent, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
    }

    /* broadcast out */
    shmem_internal_bcast(target, target, count * type_size, 0, PE_start,
                         PE_stride, PE_size, pSync + 2, 0);
}


void
shmem_internal_op_to_all_recdbl_sw(void *target, const void *source, size_t count, size_t type_size,
                                   int PE_start, int PE_stride, int PE_size,
                                   void *pWrk, long *pSync,
                                   shm_internal_op_t op, shm_internal_datatype_t datatype)
{
    int my_id = ((shmem_internal_my_pe - PE_start) / PE_stride);
    int log2_proc = 1, pow2_proc = 2;
    int i = PE_size >> 1;
    size_t wrk_size = type_size*count;
    void * const current_target = malloc(wrk_size);
    long completion = 0;
    long * pSync_extra_peer = pSync + SHMEM_REDUCE_SYNC_SIZE - 2;
    const long ps_target_ready = 1, ps_data_ready = 2;

    if (PE_size == 1) {
        if (target != source) {
            shmem_internal_copy_self(target, source, type_size * count);
        }
        free(current_target);
        return;
    }

    if (count == 0) {
        free(current_target);
        return;
    }

    while (i != 1) {
        i >>= 1;
        pow2_proc <<= 1;
        log2_proc++;
    }

    /* Currently SHMEM_REDUCE_SYNC_SIZE assumes space for 2^32 PEs; this
       parameter may be changed if need-be */
    shmem_internal_assert(log2_proc <= (SHMEM_REDUCE_SYNC_SIZE - 2));

    if (current_target)
        memcpy(current_target, (void *) source, wrk_size);
    else
        RAISE_ERROR_MSG("Failed to allocate current_target (count=%zu, type_size=%zu, size=%zuB)\n",
                        count, type_size, wrk_size);

    /* Algorithm: reduce N number of PE's into a power of two recursive
     * doubling algorithm have extra_peers do the operation with one of the
     * power of two PE's so the information is in the power of two algorithm,
     * at the end, update extra_peers with answer found by power of two team
     *
     * -target is used as "temp" buffer -- current_target tracks latest result
     * give partner current_result,
     */

    /* extra peer exchange: grab information from extra_peer so its part of
     * pairwise exchange */
    if (my_id >= pow2_proc) {
        int peer = (my_id - pow2_proc) * PE_stride + PE_start;

        /* Wait for target ready, required when source and target overlap */
        SHMEM_WAIT_UNTIL(pSync_extra_peer, SHMEM_CMP_EQ, ps_target_ready);

        shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, current_target, wrk_size, peer,
                              &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync_extra_peer, &ps_data_ready, sizeof(long), peer);
        SHMEM_WAIT_UNTIL(pSync_extra_peer, SHMEM_CMP_EQ, ps_data_ready);

    } else {
        if (my_id < PE_size - pow2_proc) {
            int peer = (my_id + pow2_proc) * PE_stride + PE_start;
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync_extra_peer, &ps_target_ready, sizeof(long), peer);

            SHMEM_WAIT_UNTIL(pSync_extra_peer, SHMEM_CMP_EQ, ps_data_ready);
            shmem_internal_reduce_local(op, datatype, count, target, current_target);
        }

        /* Pairwise exchange: (only for PE's that are within the power of 2
         * set) with every iteration, the information from each previous
         * exchange is passed forward in the new interation */

        for (i = 0; i < log2_proc; i++) {
            long *step_psync = &pSync[i];
            int peer = (my_id ^ (1 << i)) * PE_stride + PE_start;

            if (shmem_internal_my_pe < peer) {
                shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, step_psync, &ps_target_ready,
                                         sizeof(long), peer);
                SHMEM_WAIT_UNTIL(step_psync, SHMEM_CMP_EQ, ps_data_ready);

                shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, current_target,
                                      wrk_size, peer, &completion);
                shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
                shmem_internal_fence(SHMEM_CTX_DEFAULT);
                shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, step_psync, &ps_data_ready,
                                         sizeof(long), peer);
            }
            else {
                SHMEM_WAIT_UNTIL(step_psync, SHMEM_CMP_EQ, ps_target_ready);

                shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, current_target,
                                      wrk_size, peer, &completion);
                shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
                shmem_internal_fence(SHMEM_CTX_DEFAULT);
                shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, step_psync, &ps_data_ready,
                                         sizeof(long), peer);

                SHMEM_WAIT_UNTIL(step_psync, SHMEM_CMP_EQ, ps_data_ready);
            }

            shmem_internal_reduce_local(op, datatype, count,
                                        target, current_target);
        }

        /* update extra peer with the final result from the pairwise exchange */
        if (my_id < PE_size - pow2_proc) {
            int peer = (my_id + pow2_proc) * PE_stride + PE_start;

            shmem_internal_put_nb(SHMEM_CTX_DEFAULT, target, current_target, wrk_size,
                                  peer, &completion);
            shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
            shmem_internal_fence(SHMEM_CTX_DEFAULT);
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync_extra_peer, &ps_data_ready,
                                     sizeof(long), peer);
        }

        memcpy(target, current_target, wrk_size);
    }

    free(current_target);

    for (i = 0; i < SHMEM_REDUCE_SYNC_SIZE; i++)
        pSync[i] = SHMEM_SYNC_VALUE;
}


/*****************************************
 *
 * COLLECT (variable size)
 *
 *****************************************/
void
shmem_internal_collect_linear(void *target, const void *source, size_t len,
                              int PE_start, int PE_stride, int PE_size, long *pSync)
{
    size_t my_offset;
    long tmp[2];
    int peer, start_pe, i;

    /* Need 2 for lengths and barrier for completion */
    shmem_internal_assert(SHMEM_COLLECT_SYNC_SIZE >= 2 + SHMEM_BARRIER_SYNC_SIZE);

    DEBUG_MSG("target=%p, source=%p, len=%zd, PE_Start=%d, PE_stride=%d, PE_size=%d, pSync=%p\n",
              target, source, len, PE_start, PE_stride, PE_size, (void*) pSync);

    if (PE_size == 1) {
        if (target != source) shmem_internal_copy_self(target, source, len);
        return;
    }

    /* Linear prefix sum -- propagate update lengths and calculate offset */
    if (PE_start == shmem_internal_my_pe) {
        my_offset = 0;
        tmp[0] = (long) len; /* FIXME: Potential truncation of size_t into long */
        tmp[1] = 1; /* FIXME: Packing flag with data relies on byte ordering */
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, tmp, 2 * sizeof(long), PE_start + PE_stride);
    }
    else {
        /* wait for send data */
        SHMEM_WAIT_UNTIL(&pSync[1], SHMEM_CMP_EQ, 1);
        my_offset = pSync[0];

        /* Not the last guy, so send offset to next PE */
        if (shmem_internal_my_pe < PE_start + PE_stride * (PE_size - 1)) {
            tmp[0] = (long) (my_offset + len);
            tmp[1] = 1;
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, tmp, 2 * sizeof(long),
                                     shmem_internal_my_pe + PE_stride);
        }
    }

    /* Send data round-robin, ending with my PE */
    start_pe = shmem_internal_circular_iter_next(shmem_internal_my_pe,
                                                 PE_start, PE_stride,
                                                 PE_size);
    peer = start_pe;
    do {
        if (len > 0) {
            shmem_internal_put_nbi(SHMEM_CTX_DEFAULT, ((uint8_t *) target) + my_offset, source,
                                  len, peer);
        }
        peer = shmem_internal_circular_iter_next(peer, PE_start, PE_stride,
                                                 PE_size);
    } while (peer != start_pe);

    shmem_internal_barrier(PE_start, PE_stride, PE_size, &pSync[2]);

    pSync[0] = SHMEM_SYNC_VALUE;
    pSync[1] = SHMEM_SYNC_VALUE;

    for (i = 0; i < SHMEM_BARRIER_SYNC_SIZE; i++)
        pSync[2+i] = SHMEM_SYNC_VALUE;
}


/*****************************************
 *
 * COLLECT (same size)
 *
 *****************************************/
void
shmem_internal_fcollect_linear(void *target, const void *source, size_t len,
                               int PE_start, int PE_stride, int PE_size, long *pSync)
{
    long tmp = 1;
    long completion = 0;

    /* need 1 slot, plus bcast */
    shmem_internal_assert(SHMEM_COLLECT_SYNC_SIZE >= 1 + SHMEM_BCAST_SYNC_SIZE);

    if (PE_start == shmem_internal_my_pe) {
        /* Copy data into the target */
        if (source != target) shmem_internal_copy_self(target, source, len);

        /* send completion update */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &tmp, sizeof(long),
                              PE_start, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* wait for N updates */
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, PE_size);

        /* Clear pSync */
        tmp = 0;
        shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &tmp, sizeof(tmp), PE_start);
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);
    } else {
        /* Push data into the target */
        size_t offset = ((shmem_internal_my_pe - PE_start) / PE_stride) * len;
        shmem_internal_put_nb(SHMEM_CTX_DEFAULT, (char*) target + offset, source, len, PE_start,
                              &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);

        /* ensure ordering */
        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        /* send completion update */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &tmp, sizeof(long),
                              PE_start, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);
    }

    shmem_internal_bcast(target, target, len * PE_size, 0, PE_start, PE_stride,
                         PE_size, pSync + 1, 0);
}


/* Ring algorithm, in which every process sends only to its next
 * highest neighbor, each time sending the data it received in the
 * previous iteration.  This algorithm works regardless of process
 * count and is efficient at larger message sizes.
 *
 *   (p - 1) alpha + ((p - 1)/p)n beta
 */
void
shmem_internal_fcollect_ring(void *target, const void *source, size_t len,
                             int PE_start, int PE_stride, int PE_size, long *pSync)
{
    int i;
    /* my_id is the index in a theoretical 0...N-1 array of
       participating tasks */
    int my_id = ((shmem_internal_my_pe - PE_start) / PE_stride);
    int next_proc = PE_start + ((my_id + 1) % PE_size) * PE_stride;
    long completion = 0;
    long zero = 0, one = 1;

    /* need 1 slot */
    shmem_internal_assert(SHMEM_COLLECT_SYNC_SIZE >= 1);

    if (len == 0) return;

    /* copy my portion to the right place */
    shmem_internal_copy_self((char*) target + (my_id * len), source, len);

    /* send n - 1 messages to the next highest proc.  Each message
       contains what we received the previous step (including our own
       data for step 1). */
    for (i = 1 ; i < PE_size ; ++i) {
        size_t iter_offset = ((my_id + 1 - i + PE_size) % PE_size) * len;

        /* send data to me + 1 */
        shmem_internal_put_nb(SHMEM_CTX_DEFAULT, (char*) target + iter_offset, (char*) target + iter_offset,
                             len, next_proc, &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        /* send completion for this round to next proc.  Note that we
           only ever sent to next_proc and there's a shmem_fence
           between successive calls to the put above.  So a rolling
           counter is safe here. */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, pSync, &one, sizeof(long),
                              next_proc, SHM_INTERNAL_SUM, SHM_INTERNAL_LONG);

        /* wait for completion for this round */
        SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_GE, i);
    }

    /* zero out psync */
    shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, pSync, &zero, sizeof(long), shmem_internal_my_pe);
    SHMEM_WAIT_UNTIL(pSync, SHMEM_CMP_EQ, 0);
}


/* recursive doubling algorithm.  Pairs of doubling distance send
 * doubling amounts of data at each step.  This implementation only
 * supports power of two processes and is less efficient than the ring
 * algorithm at large messages.
 *
 *   log(p) alpha + (p-1)/p n beta
 */
void
shmem_internal_fcollect_recdbl(void *target, const void *source, size_t len,
                               int PE_start, int PE_stride, int PE_size, long *pSync)
{
    int my_id = ((shmem_internal_my_pe - PE_start) / PE_stride);
    int i;
    long completion = 0;
    size_t curr_offset;
    int *pSync_ints = (int*) pSync;
    int one = 1, neg_one = -1;
    int distance;

    /* need log2(num_procs) int slots.  max_num_procs is
       2^(sizeof(int)*8-1)-1, so make the math a bit easier and assume
       2^(sizeof(int) * 8), which means log2(num_procs) is always less
       than sizeof(int) * 8. */
    /* Note: pSync can be treated as a byte array rather than an int array to
     * get better cache locality.  We chose int here for portability, since SUM
     * on INT is required by the SHMEM atomics API. */
    shmem_internal_assert(SHMEM_COLLECT_SYNC_SIZE >= (sizeof(int) * 8) / (sizeof(long) / sizeof(int)));
    shmem_internal_assert(0 == (PE_size & (PE_size - 1)));

    if (len == 0) return;

    /* copy my portion to the right place */
    curr_offset = my_id * len;
    shmem_internal_copy_self((char*) target + curr_offset, source, len);

    for (i = 0, distance = 0x1 ; distance < PE_size ; i++, distance <<= 1) {
        int peer = my_id ^ distance;
        int real_peer = PE_start + (peer * PE_stride);

        /* send data to peer */
        shmem_internal_put_nb(SHMEM_CTX_DEFAULT, (char*) target + curr_offset, (char*) target + curr_offset,
                              distance * len, real_peer, &completion);
        shmem_internal_put_wait(SHMEM_CTX_DEFAULT, &completion);
        shmem_internal_fence(SHMEM_CTX_DEFAULT);

        /* mark completion for this round */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, &pSync_ints[i], &one, sizeof(int),
                              real_peer, SHM_INTERNAL_SUM, SHM_INTERNAL_INT);

        SHMEM_WAIT_UNTIL(&pSync_ints[i], SHMEM_CMP_NE, 0);

        /* this slot is no longer used, so subtract off results now */
        shmem_internal_atomic(SHMEM_CTX_DEFAULT, &pSync_ints[i], &neg_one, sizeof(int),
                              shmem_internal_my_pe, SHM_INTERNAL_SUM, SHM_INTERNAL_INT);

        if (my_id > peer) {
            curr_offset -= (distance * len);
        }
    }

    shmem_internal_quiet(SHMEM_CTX_DEFAULT);
}


void
shmem_internal_alltoall(void *dest, const void *source, size_t len,
                        int PE_start, int PE_stride, int PE_size, long *pSync)
{
    const int my_as_rank = (shmem_internal_my_pe - PE_start) / PE_stride;
    const void *dest_ptr = (uint8_t *) dest + my_as_rank * len;
    int peer, start_pe, i;

    shmem_internal_assert(SHMEM_ALLTOALL_SYNC_SIZE >= SHMEM_BARRIER_SYNC_SIZE);

    if (0 == len)
        return;

    /* Send data round-robin, ending with my PE */
    start_pe = shmem_internal_circular_iter_next(shmem_internal_my_pe,
                                                 PE_start, PE_stride,
                                                 PE_size);
    peer = start_pe;
    do {
        int peer_as_rank = (peer - PE_start) / PE_stride; /* Peer's index in active set */

        shmem_internal_put_nbi(SHMEM_CTX_DEFAULT, (void *) dest_ptr, (uint8_t *) source + peer_as_rank * len,
                              len, peer);
        peer = shmem_internal_circular_iter_next(peer, PE_start, PE_stride,
                                                 PE_size);
    } while (peer != start_pe);

    shmem_internal_barrier(PE_start, PE_stride, PE_size, pSync);

    for (i = 0; i < SHMEM_BARRIER_SYNC_SIZE; i++)
        pSync[i] = SHMEM_SYNC_VALUE;
}


void
shmem_internal_alltoalls(void *dest, const void *source, ptrdiff_t dst,
                         ptrdiff_t sst, size_t elem_size, size_t nelems,
                         int PE_start, int PE_stride, int PE_size, long *pSync)
{
    const int my_as_rank = (shmem_internal_my_pe - PE_start) / PE_stride;
    const void *dest_base = (uint8_t *) dest + my_as_rank * nelems * dst * elem_size;
    int peer, start_pe, i;

    shmem_internal_assert(SHMEM_ALLTOALLS_SYNC_SIZE >= SHMEM_BARRIER_SYNC_SIZE);

    if (0 == nelems)
        return;

    /* Implementation note: Neither OFI nor Portals presently has support for
     * noncontiguous data at the target of a one-sided operation.  I'm not sure
     * of the best communication schedule for the resulting doubly-nested
     * all-to-all.  It may be preferable in some scenarios to exchange the
     * loops below to spread out the communication and decrease the exposure to
     * incast.
     */

    /* Send data round-robin, ending with my PE */
    start_pe = shmem_internal_circular_iter_next(shmem_internal_my_pe,
                                                 PE_start, PE_stride,
                                                 PE_size);
    peer = start_pe;
    do {
        size_t i;
        int peer_as_rank    = (peer - PE_start) / PE_stride; /* Peer's index in active set */
        uint8_t *dest_ptr   = (uint8_t *) dest_base;
        uint8_t *source_ptr = (uint8_t *) source + peer_as_rank * nelems * sst * elem_size;

        for (i = nelems ; i > 0; i--) {
            shmem_internal_put_scalar(SHMEM_CTX_DEFAULT, (void *) dest_ptr, (uint8_t *) source_ptr,
                                     elem_size, peer);

            source_ptr += sst * elem_size;
            dest_ptr   += dst * elem_size;
        }
        peer = shmem_internal_circular_iter_next(peer, PE_start, PE_stride,
                                                 PE_size);
    } while (peer != start_pe);

    shmem_internal_barrier(PE_start, PE_stride, PE_size, pSync);

    for (i = 0; i < SHMEM_BARRIER_SYNC_SIZE; i++)
        pSync[i] = SHMEM_SYNC_VALUE;
}
