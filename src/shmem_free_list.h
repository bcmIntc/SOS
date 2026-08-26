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

#ifndef SHMEM_FREE_QUEUE_H
#define SHMEM_FREE_QUEUE_H

#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include "shmem_internal.h"

struct shmem_free_list_item_t {
    struct shmem_free_list_item_t *next;
};
typedef struct shmem_free_list_item_t shmem_free_list_item_t;

struct shmem_free_list_alloc_t {
    struct shmem_free_list_alloc_t *next;
};
typedef struct shmem_free_list_alloc_t shmem_free_list_alloc_t;

typedef void (*shmem_free_list_item_init_fn_t)(shmem_free_list_item_t *item);

struct shmem_free_list_t {
    size_t element_size;
    uint64_t nalloc;
    uint64_t alloc_size;
    uint64_t pool_size;
    char *pool;
    size_t pool_ofs;
    shmem_free_list_item_init_fn_t init_fn;
    shmem_free_list_alloc_t *allocs;
    shmem_free_list_item_t* head;
#ifdef ENABLE_THREADS
    shmem_internal_mutex_t lock;
#endif
};
typedef struct shmem_free_list_t shmem_free_list_t;

/* Elements are handed out in chunks: one chunk header followed by
 * SHMEM_FREE_LIST_NUM_ELEMENTS elements.  A preallocated pool therefore holds
 * whole chunks, and max_pool_cnt -- an element count, which is what every caller
 * has -- rounds up to the chunk count that supplies it.
 *
 * A caller that must reserve the pool's memory before creating the list sizes the
 * reserve with SHMEM_FREE_LIST_POOL_SIZE, which is what shmem_free_list_init
 * itself uses, so the reserve cannot drift away from the allocation. */
#define SHMEM_FREE_LIST_NUM_ELEMENTS 2
#define SHMEM_FREE_LIST_POOL_SIZE(element_size, max_pool_cnt)               \
    ((sizeof(shmem_free_list_alloc_t) +                                     \
      SHMEM_FREE_LIST_NUM_ELEMENTS * (size_t) (element_size)) *             \
     (((size_t) (max_pool_cnt) + SHMEM_FREE_LIST_NUM_ELEMENTS - 1) /        \
      SHMEM_FREE_LIST_NUM_ELEMENTS))

shmem_free_list_t* shmem_free_list_init(size_t element_size,
                                        shmem_free_list_item_init_fn_t init_fn,
					size_t max_pool_cnt);
void shmem_free_list_destroy(shmem_free_list_t *fl);
int shmem_free_list_more(shmem_free_list_t *fl);


static inline
void*
shmem_free_list_alloc(shmem_free_list_t *fl)
{
    shmem_free_list_item_t *item = NULL;
    int ret;

    if (NULL == fl->head) {
        ret = shmem_free_list_more(fl);
        if (0 != ret) return item;
    }
    shmem_internal_assert(NULL != fl->head);

    item = fl->head;
    fl->head = item->next;
    fl->nalloc++;

    return item;
}


static inline
void
shmem_free_list_free(shmem_free_list_t *fl, void *data)
{
    shmem_free_list_item_t *item = (shmem_free_list_item_t*) data;

    item->next = fl->head;
    fl->head = item;
    fl->nalloc--;
}


static inline
void
shmem_free_list_lock(shmem_free_list_t *fl)
{
    SHMEM_MUTEX_LOCK(fl->lock);
}


static inline
void
shmem_free_list_unlock(shmem_free_list_t *fl)
{
    SHMEM_MUTEX_UNLOCK(fl->lock);
}

#endif
