/* -*- C -*-
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S.  Government
 * retains certain rights in this software.
 *
 * Copyright (c) 2018 Intel Corporation. All rights reserved.
 * This software is available to you under the BSD license.
 *
 * This file is part of the Sandia OpenSHMEM software package. For license
 * information, see the LICENSE file in the top level directory of the
 * distribution.
 *
 */

/* This header depends on 'config.h', which cannot be included here. Please
 * include 'config.h' before including this file, 'shmem_env_defs.h'
 */

/* SOS_ENV( name, kind, default, category, short description )
 *
 * Kinds: long, size, bool, string
 * Categories: openshmem, other, collectives, intranode, transport
 */
SHMEM_INTERNAL_ENV_DEF(INFO, bool, false, SHMEM_INTERNAL_ENV_CAT_OPENSHMEM,
                       "Print library information message at startup")
SHMEM_INTERNAL_ENV_DEF(VERSION, bool, true, SHMEM_INTERNAL_ENV_CAT_OPENSHMEM,
                       "Print library version at startup")
SHMEM_INTERNAL_ENV_DEF(DEBUG, bool, false, SHMEM_INTERNAL_ENV_CAT_OPENSHMEM,
                       "Enable debugging messages")
SHMEM_INTERNAL_ENV_DEF(SYMMETRIC_SIZE, size, 512*1024*1024, SHMEM_INTERNAL_ENV_CAT_OPENSHMEM,
                       "Symmetric heap size")

#ifdef __linux__
SHMEM_INTERNAL_ENV_DEF(SYMMETRIC_HEAP_USE_HUGE_PAGES, bool, true, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Use Linux huge pages for symmetric heap")
SHMEM_INTERNAL_ENV_DEF(SYMMETRIC_HEAP_PAGE_SIZE, size, 2*1024*1024, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Page size to use for huge pages")
#endif
#if defined(ENABLE_REMOTE_VIRTUAL_ADDRESSING) && defined(__linux__) && !defined(DISABLE_ASLR_CHECK_AC)
SHMEM_INTERNAL_ENV_DEF(DISABLE_ASLR_CHECK, bool, false, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Disable check for address space layout randomization (ASLR)")
#endif

SHMEM_INTERNAL_ENV_DEF(SYMMETRIC_HEAP_USE_MALLOC, bool, false, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Allocate the symmetric heap using malloc")
SHMEM_INTERNAL_ENV_DEF(BOUNCE_SIZE, size, DEFAULT_BOUNCE_SIZE, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Maximum message size to bounce buffer")
SHMEM_INTERNAL_ENV_DEF(MAX_BOUNCE_BUFFERS, size, 128, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Maximum number of bounce buffers per context")
SHMEM_INTERNAL_ENV_DEF(TRAP_ON_ABORT, bool, false, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Generate trap if the program aborts or calls shmem_global_exit")

SHMEM_INTERNAL_ENV_DEF(COLL_CROSSOVER, long, 4, SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Crossover between linear and tree collectives (num. PEs)")
SHMEM_INTERNAL_ENV_DEF(COLL_SIZE_CROSSOVER, size, 16384, SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Crossover between latency and bandwidth optimized collectives (msg. size)")
SHMEM_INTERNAL_ENV_DEF(COLL_RADIX, long, 4, SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Radix for tree-based collectives")
SHMEM_INTERNAL_ENV_DEF(BARRIER_ALGORITHM, string, "auto", SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Algorithm for barrier.  Options are auto, linear, tree, dissem, hierarchical")
SHMEM_INTERNAL_ENV_DEF(HIER_BARRIER_THRESHOLD, long, 2, SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Minimum local PE count per node to auto-select the hierarchical barrier")
SHMEM_INTERNAL_ENV_DEF(COLLECTIVES_DEBUG, bool, 0, SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Print collectives specific debug:")
SHMEM_INTERNAL_ENV_DEF(BCAST_ALGORITHM, string, "auto", SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Algorithm for broadcast.  Options are auto, linear, tree")
SHMEM_INTERNAL_ENV_DEF(REDUCE_ALGORITHM, string, "auto", SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Algorithm for reductions.  Options are auto, linear, tree, recdbl")
SHMEM_INTERNAL_ENV_DEF(SCAN_ALGORITHM, string, "auto", SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Algorithm for scan.  Options are linear, ring")
SHMEM_INTERNAL_ENV_DEF(COLLECT_ALGORITHM, string, "auto", SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Algorithm for collect.  Options are auto, linear")
SHMEM_INTERNAL_ENV_DEF(FCOLLECT_ALGORITHM, string, "auto", SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                       "Algorithm for fcollect.  Options are auto, linear, ring, recdbl")
SHMEM_INTERNAL_ENV_DEF(BARRIERS_FLUSH, bool, false, SHMEM_INTERNAL_ENV_CAT_COLLECTIVES,
                        "Flush stdout and stderr on barrier")

SHMEM_INTERNAL_ENV_DEF(TEAMS_MAX, long, DEFAULT_TEAMS_MAX, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Maximum number of teams per PE")
SHMEM_INTERNAL_ENV_DEF(TEAM_SHARED_ONLY_SELF, bool, false, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Include only the self PE in SHMEM_TEAM_SHARED")

#ifdef USE_CMA
SHMEM_INTERNAL_ENV_DEF(CMA_PUT_MAX, size, 8*1024, SHMEM_INTERNAL_ENV_CAT_INTRANODE,
                       "Size below which to use CMA for puts")
SHMEM_INTERNAL_ENV_DEF(CMA_GET_MAX, size, 16*1024, SHMEM_INTERNAL_ENV_CAT_INTRANODE,
                       "Size below which to use CMA for gets")
#endif /* USE_CMA */

#ifdef USE_OFI
SHMEM_INTERNAL_ENV_DEF(OFI_ATOMIC_CHECKS_WARN, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Display warnings about unsupported atomic operations")
SHMEM_INTERNAL_ENV_DEF(OFI_PROVIDER, string, "auto", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Provider that should be used by the OFI transport")
SHMEM_INTERNAL_ENV_DEF(OFI_FABRIC, string, "auto", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Fabric that should be used by the OFI transport")
SHMEM_INTERNAL_ENV_DEF(OFI_DOMAIN, string, "auto", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Fabric domain that should be used by the OFI transport")
SHMEM_INTERNAL_ENV_DEF(OFI_TX_POLL_LIMIT, long, DEFAULT_POLL_LIMIT, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Put completion poll limit")
SHMEM_INTERNAL_ENV_DEF(OFI_RX_POLL_LIMIT, long, DEFAULT_POLL_LIMIT, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Get completion poll limit")
SHMEM_INTERNAL_ENV_DEF(OFI_STX_MAX, long, 1, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Maximum number of STX contexts per PE")
SHMEM_INTERNAL_ENV_DEF(OFI_STX_AUTO, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Automatically partition the STX pool evenly across PEs on each compute node")
SHMEM_INTERNAL_ENV_DEF(OFI_STX_THRESHOLD, long, 1, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Maximum number of shared contexts per STX before allocating a new STX resource")
SHMEM_INTERNAL_ENV_DEF(OFI_STX_ALLOCATOR, string, "round-robin", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Algorithm for allocating STX resources to contexts")
SHMEM_INTERNAL_ENV_DEF(OFI_STX_DISABLE_PRIVATE, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Disallow private contexts from having exclusive STX access")
SHMEM_INTERNAL_ENV_DEF(OFI_DISABLE_MULTIRAIL, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Disable usage of multirail functionality")
SHMEM_INTERNAL_ENV_DEF(OFI_DISABLE_SINGLE_EP, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Disable single endpoint resource optimization (enable separate Tx and Rx EPs)")
SHMEM_INTERNAL_ENV_DEF(OFI_TCLASS, string, "unspec", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Traffic class requested for transmit operations.  Options are unspec, "
                       "best_effort, low_latency, dedicated_access, bulk_data, scavenger, "
                       "network_ctrl, or dscp:N (N = 0-63)")
SHMEM_INTERNAL_ENV_DEF(OFI_COLL_CONTEXT, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Give the hierarchical barrier's internode pSync puts a dedicated "
                       "internal context, one extra transmit endpoint per PE, on the same "
                       "traffic class as user data.  Separates the barrier's queueing from the "
                       "class it runs on: this knob alone changes no class, and "
                       "SHMEM_OFI_COLL_TCLASS also implies it")
SHMEM_INTERNAL_ENV_DEF(OFI_COLL_TCLASS, string, "unspec", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Traffic class for the dedicated collective context, separate from the "
                       "class SHMEM_OFI_TCLASS gives user data.  Same options as "
                       "SHMEM_OFI_TCLASS.  Setting it to anything but unspec creates the "
                       "context whether or not SHMEM_OFI_COLL_CONTEXT is set.  When unspec "
                       "(default) the context, if SHMEM_OFI_COLL_CONTEXT created one, requests "
                       "no class of its own and inherits SHMEM_OFI_TCLASS")
SHMEM_INTERNAL_ENV_DEF(OFI_COLL_CTX_FIRST, bool, false, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Open the dedicated collective context before the target endpoint, so its "
                       "traffic class is the first one this PE asks for.  Measured on CXI this "
                       "changes nothing: SHMEM_OFI_COLL_TCLASS is refused on any endpoint but "
                       "the target one in either order.  Kept because it separates creation "
                       "order from the endpoint attributes that do decide it, which "
                       "SHMEM_OFI_COLL_CTX_EP_PROBE varies")
SHMEM_INTERNAL_ENV_DEF(OFI_COLL_CTX_EP_PROBE, long, 0, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Diagnostic bitmask.  CXI refuses a traffic class on every endpoint but "
                       "the target one, always as TYPE: RESTRICTED, so the provider picks the "
                       "profile type from the endpoint's attributes.  This alters the collective "
                       "context's transmit attributes to match the target endpoint's, one at a "
                       "time: 1 clears FI_DELIVERY_COMPLETE, 2 narrows tx_attr->caps to "
                       "FI_RMA|FI_ATOMIC, 3 does both.  Bit 0 weakens what a put on that context "
                       "promises, so read the fabric counters and not the barrier's timings")
#endif

#ifdef USE_UCX
SHMEM_INTERNAL_ENV_DEF(PROGRESS_INTERVAL, long, 1000, SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Polling interval for progress thread in microseconds (0 to disable)")
#endif

#ifdef ENABLE_PMI_MPI
SHMEM_INTERNAL_ENV_DEF(MPI_THREAD_LEVEL, string, "MPI_THREAD_SINGLE", SHMEM_INTERNAL_ENV_CAT_TRANSPORT,
                       "Specify the MPI threading level when MPI is used as the process manager")
#endif

SHMEM_INTERNAL_ENV_DEF(BACKTRACE, string, "", SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Specify the mechanism to use for backtracing on failure")

SHMEM_INTERNAL_ENV_DEF(BOUNCE_MLOCK, bool, false, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Lock bounce buffer memory preventing buffers from being paged out to swap")
SHMEM_INTERNAL_ENV_DEF(BOUNCE_SHEAP, bool, true, SHMEM_INTERNAL_ENV_CAT_OTHER,
                       "Allocate bounce buffers using symmetric heap, if supported by transport")
