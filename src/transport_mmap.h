/* -*- C -*-
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S.  Government
 * retains certain rights in this software.
 *
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 * This software is available to you under the BSD license.
 *
 * This file is part of the Sandia OpenSHMEM software package. For license
 * information, see the LICENSE file in the top level directory of the
 * distribution.
 *
 */

#ifndef TRANSPORT_MMAP_H
#define TRANSPORT_MMAP_H

#include <string.h>
#include <inttypes.h>

// bman
#include <immintrin.h>

//#ifdef MAP_POPULATE
//  #undef MAP_POPULATE
//  #define MAP_POPULATE 0        // Run this to disable my hack to mmap(). Comment out to enable it, using the default value.
//#endif

//#define LOCK_PAGES              // locks all shm pages
//#define BMAN_HACKING            // turns on test code for memcpy replacements/hand-coded
//#define USE_NONTEMPORAL_ALIGNED_MEMCPY  // requires BMAN_HACKING to also be set for this to take effect
//#define BMAN_TRACK_ALIGNMENT    // independent of other flags

// These 2 are mutex, not enforced
//#define USE_CLDEMOTE_NOBARRIER            // turns on cldemote w/o memory barrier
//#define USE_CLDEMOTE_BARRIER              // turns on cldemote w/memory barrier

// PAPI is being annoying and not giving me access to 'PAPI_L1_DCA' for L1 accesses.
// Use this instead of PAPI. Still cannot get L1D$ write accesses.
// NOTE: 'USE_PERFMON_MMAP/ATM' configured by make (Set the -DUSE_PERFMON_MMAP xor _ATM cflag during configuration).
#ifdef USE_PERFMON_ATM
 #include <linux/perf_event.h>
 #define MAX_EVENTS 100         // TODO: resolve with NUM_EVENTS_MAX
 #define MAX_COUNTS 1024        // #of counter reads per event
 #define NUM_MEASUREMENTS MAX_COUNTS
 #define NUM_EVENTS_MAX 16
 #define NUM_CONSTANTS 4
 typedef struct {
    long long tdiff[MAX_COUNTS]; // holds the stop-start count for a given event.
 } Record_t;
 typedef struct {
    char key[256];              // event name
    int value;                  // event index into eventReadBuffer[]]
 } EventEntry;
 extern int                    diff_count;
 extern int                    eventCount;
 extern long long              start_counters[MAX_EVENTS];
 extern long long              end_counters[MAX_EVENTS];
 extern struct perf_event_attr perf_event[NUM_EVENTS_MAX];
 extern int                    perf_event_fd[NUM_EVENTS_MAX];
 extern int                    perfmon_overhead;
 extern EventEntry             eventNameToIndexMap[MAX_EVENTS];
 extern Record_t               eventReadBuffer[MAX_EVENTS];         // holds the counter data
 extern unsigned int           non_working_events;
#endif

// TODO: combine these two ifdefs

#ifdef USE_PERFMON_MMAP
 // Set to use my hand-coded copy functions. Unset to use default memcpy.
 #define PROFILE_MEMCPY          // look at the put's memcpy perf

 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <string.h>
 #include <sys/ioctl.h>
 #include <fcntl.h>
 #include <linux/perf_event.h>
 #include <fcntl.h>
 #include <sys/syscall.h>

 #define MAX_EVENTS 100         // TODO: resolve with NUM_EVENTS_MAX
 #define MAX_COUNTS 1024        // #of counter reads per event
 #define NUM_MEASUREMENTS MAX_COUNTS 
 #define NUM_EVENTS_MAX 16
 #define NUM_CONSTANTS 4

 typedef struct {
    long long tdiff[MAX_COUNTS];                // holds the stop-start count for a given event.
 } Record_t; 
 typedef struct {
    char key[256];              // event name
    int value;                  // event index into eventReadBuffer[]]
 } EventEntry;

 extern struct perf_event_attr perf_event[NUM_EVENTS_MAX];
 extern int perf_event_fd[NUM_EVENTS_MAX];
 extern int diff_count;
 extern int eventCount;
 extern int eventSet;
 extern Record_t eventReadBuffer[MAX_EVENTS];   // holds the counter data
 extern unsigned int non_working_events;                 // a bitmask where each bit represents a read-in counter. If set, means is disabled (i.e. open failed).
#endif

// bman temp: globals to track #aligned calls we get
extern int cnt;    // total 64 byte calls
extern int aligned_cnt; // total aligned
extern int unaligned_cnt; // total unaligned
extern int aligned_src_cnt;
extern int aligned_dest_cnt;
extern int buff_source_size_aligned;
extern int buff_adjusted_dest_size_aligned;
extern int total_count;
extern int buff_source_64_aligned;
extern int buff_adjusted_dest_64_aligned;
extern int buff_adjusted_dest_size_largerThan64_aligned;
extern int buff_source_size_largerThan64_aligned;
//

struct shmem_transport_mmap_peer_info_t {
    void *data_attach_ptr;
    void *heap_attach_ptr;
    void *data_ptr;
    void *heap_ptr;
};

extern struct shmem_transport_mmap_peer_info_t *shmem_transport_mmap_peers;

#ifdef ENABLE_ERROR_CHECKING
#define MMAP_GET_REMOTE_ACCESS(target, rank, ptr)                       \
    do {                                                                \
        if (((void*) target > shmem_internal_data_base) &&              \
            ((char*) target < (char*) shmem_internal_data_base + shmem_internal_data_length)) { \
            ptr = (char*) target - (char*) shmem_internal_data_base +   \
                (char*) shmem_transport_mmap_peers[rank].data_ptr;      \
        } else if (((void*) target >= shmem_internal_heap_base) &&      \
                   ((char*) target < (char*) shmem_internal_heap_base + shmem_internal_heap_length)) { \
            ptr = (char*) target - (char*) shmem_internal_heap_base +   \
                (char*) shmem_transport_mmap_peers[rank].heap_ptr;      \
        } else {                                                        \
            ptr = NULL;                                                 \
        }                                                               \
    } while (0)
#else
#define MMAP_GET_REMOTE_ACCESS(target, rank, ptr)                       \
    do {                                                                \
        if ((void*) target < shmem_internal_heap_base) {                \
            ptr = (char*) target - (char*) shmem_internal_data_base +   \
                (char*) shmem_transport_mmap_peers[rank].data_ptr;      \
        } else {                                                        \
            ptr = (char*) target - (char*) shmem_internal_heap_base +   \
                (char*) shmem_transport_mmap_peers[rank].heap_ptr;      \
        }                                                               \
    } while (0)
#endif

int shmem_transport_mmap_init(void);

int shmem_transport_mmap_startup(void);

int shmem_transport_mmap_fini(void);


static inline
void *
shmem_transport_mmap_ptr(const void *target, int pe, int noderank)
{
    char *remote_ptr;

    MMAP_GET_REMOTE_ACCESS(target, noderank, remote_ptr);
    return remote_ptr;
}




#ifdef BMAN_HACKING

//////// bman: Targetted for 64 Bytes copies ////////////////
#define LOAD(reg,p)   __asm__ volatile ("vmovaps %1, %0\n": "=x"(reg): "m"(p));
#define LOADNT(reg,p) __asm__ volatile ("vmovntdqa %1, %0\n": "=x"(reg): "m"(p));

// CLDEMOTE: it takes a byte address and handles the entire cacheline
__attribute__((aligned(64)))
inline __attribute__((always_inline)) void demote_with_barrier_1(void *dst) 
{
    __asm__ __volatile__("cldemote (%0)" : : "r"(dst) : "memory");      // memory clobber results in memory barrier, preventing re-ording
}

__attribute__((aligned(64)))
inline __attribute__((always_inline)) void demote_without_barrier_1(void *dst) 
{
    __asm__ __volatile__("cldemote (%0)" : : "r"(dst));
}

// For 64B only
#include <stdint.h>

// Handles straddle
__attribute__((aligned(64)))
inline __attribute__((always_inline)) void demote_with_barrier(void *dst) 
{
    uintptr_t addr = (uintptr_t)dst;
    
    // Demote the first cache line
    __asm__ __volatile__("cldemote (%0)" : : "r"(addr) : "memory");

    // If the address is not cache-line aligned, also demote the second cache line
    if (addr % 64) {
        __asm__ __volatile__("cldemote (%0)" : : "r"(addr + 64) : "memory");
    }
}

__attribute__((aligned(64)))
inline __attribute__((always_inline)) void demote_without_barrier(void *dst)
{
    uintptr_t addr = (uintptr_t)dst;

    // Demote the first cache line
    __asm__ __volatile__("cldemote (%0)" : : "r"(addr));

    // If the address is not cache-line aligned, also demote the second cache line
    if (addr % 64) {
        __asm__ __volatile__("cldemote (%0)" : : "r"(addr + 64));
    }
}

// Arb
#include <stddef.h>

__attribute__((aligned(64)))
inline __attribute__((always_inline)) void demote_with_barrier_arb(void *dst, size_t size) 
{
    uintptr_t start = (uintptr_t)dst;
    uintptr_t end = start + size;
    
    // Align start to the nearest cache line boundary
    uintptr_t cl_start = start & ~(uintptr_t)(63);
    uintptr_t cl_end = (end + 63) & ~(uintptr_t)(63); // Round up to next cache line if needed

    // Iterate over all affected cache lines
    for (uintptr_t addr = cl_start; addr < cl_end; addr += 64) {
        __asm__ __volatile__("cldemote (%0)" : : "r"(addr) : "memory");
    }
}

// AVX-512 (aligned)
//__attribute__((aligned(64)))
//inline __attribute__((always_inline)) 
static void mm512_copy64B_aligned(void *dst, const void *src, size_t notused)
{
    __m512i r0 = _mm512_load_si512(src);
    _mm512_store_si512(dst, r0);
}

// AVX-512 (un-aligned)
//__attribute__((aligned(64)))
//inline __attribute__((always_inline)) 
static void mm512_copy64B_unaligned(void *dst, const void *src, size_t notused)
{
    __m512i r0 = _mm512_loadu_si512(src);
    _mm512_storeu_si512(dst, r0);
}

//__attribute__((aligned(64)))
//inline __attribute__((always_inline)) 
static void mm512_copy64B_src_aligned_dest_unaligned(void *dst, const void *src, size_t notused)
{
    __m512i r0 = _mm512_loadu_si512(src);
    _mm512_storeu_si512(dst, r0);
}

//__attribute__((aligned(64)))
//inline __attribute__((always_inline)) 
static void mm512_copy64B_src_unaligned_dest_aligned(void *dst, const void *src, size_t notused)
{
    __m512i r0 = _mm512_loadu_si512(src);
    _mm512_store_si512(dst, r0);
}

#if 0
#define mm512_copy64B_unaligned(dst, src) do { \
    __m512i r0 = _mm512_loadu_si512((src));    \
    _mm512_storeu_si512((dst), r0);            \
} while (0)

// AVX-512 (source aligned, destination unaligned)
//__attribute__((aligned(64)))
#define mm512_copy64B_src_aligned_dest_unaligned(dst, src) do {   \
    __m512i r0 = _mm512_load_si512((src));                        \
    _mm512_storeu_si512((dst), r0);                               \
} while (0)

// AVX-512 (source unaligned, destination aligned)
//__attribute__((aligned(64)))
#define mm512_copy64B_src_unaligned_dest_aligned(dst, src) do {   \
    __m512i r0 = _mm512_loadu_si512((src));                       \
    _mm512_store_si512((dst), r0);                                \
} while(0)
#endif

__attribute__((aligned(64)))
inline __attribute__((always_inline)) void non_temporal_copy64B_aligned(void *dst, void *src)
{
    __m512i r0 = _mm512_stream_load_si512(src);
    _mm512_stream_si512(dst, r0);
}

// not used yet
__attribute__((aligned(64)))
inline __attribute__((always_inline)) void memcpy_generic_prefers_aligned_64B(void *dst, const void *src, size_t len) 
{
    size_t i;
    __m512i* dest = (__m512i*)dst;
    const __m512i* source = (const __m512i*)src;

    // Process 64 bytes at a time using AVX512
    for (i = 0; i < len / 64; i++) {
        _mm512_store_epi8(&dest[i], _mm512_loadu_epi8(&source[i]));
    }

    // Copy any remaining data byte-by-byte
    for (i = len - (len % 64); i < len; i++) {
        ((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
    }
}

// Naive implementation (non-performant)
__attribute__((aligned(64)))
inline __attribute__((always_inline)) void copy_64_bytes(const void *src, void *dst) 
{
    __asm__ volatile (
        "rep movsq"
        : /* no outputs */
        : "S"(src), "D"(dst), "c"(8)  // `c` specifies the number of 8-byte chunks
        : "memory"
    );
}

#define is_aligned(src, len) (((uintptr_t)(src) % (len)) == 0)

// Jump table. **Note: tuned for 64 byte xfers
__attribute__((aligned(64)))
static void (*jump_table[8])(void *, const void *, size_t) = 
{
    memcpy, memcpy, memcpy, memcpy,                 // '000'-'011'. These are not 64-byte transfers, so just use the default memcpy.
    mm512_copy64B_unaligned,                        // '100'. Start 64-byte special handling. Use hand-coded routines.
    mm512_copy64B_src_unaligned_dest_aligned,       // '101'
    mm512_copy64B_src_aligned_dest_unaligned,       // '110'
    mm512_copy64B_aligned                           // '111'
};

/////////////////////////////////////////////////////////////
#endif

static inline
void
shmem_transport_mmap_put(void *target, const void *source, size_t len,
                          int pe, int noderank)
{
    char *remote_ptr;
   

    MMAP_GET_REMOTE_ACCESS(target, noderank, remote_ptr);

#ifdef BMAN_HACKING 
    //_mm_prefetch((const char *)source,     _MM_HINT_T0); // Prefetch source to L1 cache. bman: expect little since we do a load next.
    //_mm_prefetch((const char *)remote_ptr, _MM_HINT_T0); // Prefetch source to L1 cache.  bman: this could actually hurt if not write-allocate.
    //_mm_prefetch((const char *)source, _MM_HINT_T0); // Prefetch source to L1 cache.  bman: this could actually hurt if not write-allocate.
#endif

#ifdef ENABLE_ERROR_CHECKING
    if (NULL == remote_ptr) {
        RAISE_ERROR_MSG("target (0x%"PRIXPTR") outside of symmetric areas\n",
                        (uintptr_t) target);
    }
#endif

#ifdef BMAN_TRACK_ALIGNMENT
    // bman: check to see if the addresses are aligned in any way
    total_count++;
    if (is_aligned(source, len))        buff_source_size_aligned++;
    if (is_aligned(remote_ptr, len))    buff_adjusted_dest_size_aligned++;
    if (is_aligned(source, 64))         buff_source_64_aligned++;
    if (is_aligned(remote_ptr, 64))     buff_adjusted_dest_64_aligned++;
    if (len > 64) 
    {
        if (is_aligned(remote_ptr, 64)) buff_adjusted_dest_size_largerThan64_aligned++;
        if (is_aligned(source, 64))     buff_source_size_largerThan64_aligned++;
    }
    if (64 == len) 
    {
        // see what the adresses look like
        if (0 == pe)
            printf("%p, %p\n", source, remote_ptr);

        cnt++;
        if (is_aligned(source, 64) && is_aligned(remote_ptr, 64)) 
        {
            aligned_cnt++;
            if (is_aligned(source, 64))     aligned_src_cnt++;
            if (is_aligned(remote_ptr, 64)) aligned_dest_cnt++;
        }
        else
        {
            unaligned_cnt++;
        }
    }
#endif

#ifdef PROFILE_MEMCPY
 #ifdef USE_PERFMON_MMAP
    // latch start counters. Note: we read the entire event-set, so need to use 'eventCount' as the iterator.
    long long start_counters[MAX_EVENTS];
    long long end_counters[MAX_EVENTS];
    if ((non_working_events & (1 << 0)) == 0)
    {
        ioctl(perf_event_fd[0], PERF_EVENT_IOC_RESET, 0);       // set counter to 0
        ioctl(perf_event_fd[0], PERF_EVENT_IOC_ENABLE, 0);      // start counter
        read(perf_event_fd[0], &start_counters[0], sizeof(start_counters[0]));
    }
    else
    {
        fprintf(stderr, "ERROR: no working events.\n");
        exit(EXIT_FAILURE);
    }
 #endif
#endif

#ifndef BMAN_HACKING
    memcpy(remote_ptr, source, len);
#else
    // bman testing

    // Compute the index: 3-bit value indicating 64byte message size, plus alignment of src and dest
    int index = (len == 64) << 2 | (( (uintptr_t)source & 63) == 0) << 1 | (( (uintptr_t)remote_ptr & 63) == 0);

    // Jump!
    jump_table[index](remote_ptr, source, len);

    // Bump this line down to the LLC (should help in theory for !HT)
  #ifdef USE_CLDEMOTE_BARRIER
    demote_with_barrier(remote_ptr);
  #endif
  #ifdef USE_CLDEMOTE_NOBARRIER
    demote_without_barrier(remote_ptr);
  #endif
#endif // BMAN_HACKING

#ifdef PROFILE_MEMCPY
    // latch stop counters
  #ifdef USE_PERFMON_MMAP
    // Stop the event
    if ((non_working_events & (1 << 0)) == 0) {
        ioctl(perf_event_fd[0], PERF_EVENT_IOC_DISABLE, 0);
    }
    else {
        fprintf(stderr, "ERROR: no working events.\n");
        exit(EXIT_FAILURE);
    }

    // Read result
    if ((non_working_events & (1 << 0)) == 0) {
        read(perf_event_fd[0], &end_counters[0], sizeof(end_counters[0]));    
    }
    else {
        fprintf(stderr, "ERROR: no working events.\n");
        exit(EXIT_FAILURE);
    }
  #endif

    // Now fill in the tracking structure
    for (int x=0; x < eventCount; x++) {
        if (non_working_events & (1 << x)) {
            eventReadBuffer[x].tdiff[diff_count] = 666;         // mark of the devil means we have an issue
        }
        else {
            eventReadBuffer[x].tdiff[diff_count] = end_counters[x] - start_counters[x];
        }
    }
    diff_count = (diff_count + 1) % MAX_COUNTS;     // rollover (moved this from inside the loop)
#endif
}


static inline
void
shmem_transport_mmap_get(void *target, const void *source, size_t len,
                          int pe, int noderank)
{
    char *remote_ptr;

    MMAP_GET_REMOTE_ACCESS(source, noderank, remote_ptr);
#ifdef ENABLE_ERROR_CHECKING
    if (NULL == remote_ptr) {
        RAISE_ERROR_MSG("target (0x%"PRIXPTR") outside of symmetric areas\n",
                        (uintptr_t) target);
    }
#endif

#ifndef BMAN_HACKING
    memcpy(target, remote_ptr, len);
#else
  #if 0
    if (len == 64)
    {
        //if ( (((uintptr_t)source & 0x3F) == 0) && (((uintptr_t)remote_ptr & 0x3F) == 0) )
        if (is_aligned(source, 64) && is_aligned(remote_ptr, 64))
        {
            mm512_copy64B_aligned(remote_ptr, source, 666);
        }
        else
        {
            mm512_copy64B_unaligned(remote_ptr, source, 666);
        }
        return;
    }
  #endif
    memcpy(remote_ptr, source, len);
#endif
}

#endif
