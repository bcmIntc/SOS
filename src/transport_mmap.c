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

#include "config.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#define SHMEM_INTERNAL_INCLUDE
#include "shmem.h"
#include "shmem_internal.h"
#include "shmem_comm.h"
#include "runtime.h"
#include "transport_mmap.h"

#define MPIDI_OFI_SHMGR_NAME_MAXLEN (128)
#define MPIDI_OFI_SHMGR_NAME_PREFIX "/sos_shm_mmap_area"


// bman
#ifdef USE_TSX_ATOMIC
 volatile int takenCount=666;
 volatile int totalCount=666;
#endif

#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)
 #include <ctype.h>
 int diff_count = 0;
 int eventCount = 0;

 long long              start_counters[MAX_EVENTS];
 long long              end_counters[MAX_EVENTS];

 struct perf_event_attr perf_event[NUM_EVENTS_MAX];
 int    perf_event_fd[NUM_EVENTS_MAX];
 int    perfmon_overhead = 0;
 unsigned int non_working_events = 0xFFFFFFFF;        // a bitmask where each bit represents a read-in counter. If set, means is disabled (i.e. open failed). Init to all nonworking.
 // NOTE: ^ TODO: also needs sync with size constants. I have 3 and none agree (16, 100 and here 32 implied).

 // Define a struct to hold key-value pairs
 // Event 'map'
 EventEntry eventNameToIndexMap[MAX_EVENTS];
 Record_t eventReadBuffer[MAX_EVENTS];         // holds the counter data
#endif

int cnt;
int aligned_cnt;
int unaligned_cnt;
int aligned_src_cnt;
int aligned_dest_cnt;
int buff_source_size_aligned;
int buff_adjusted_dest_size_aligned;
int total_count;
int buff_adjusted_dest_64_aligned;
int buff_source_64_aligned;
int buff_adjusted_dest_size_largerThan64_aligned;
int buff_source_size_largerThan64_aligned;
// /bman



static void shm_create_key(char *key, size_t max_size, unsigned pe, size_t num) {
    snprintf(key, max_size, "%s-%u-%zu", MPIDI_OFI_SHMGR_NAME_PREFIX, pe, num);
}


static void *shm_create_region(char* base, const char *key, size_t shm_size) {
  if (shm_size == 0) return NULL;

    // bman
    //printf("==>+shm_create_region(): shm_size = %ld \n", shm_size); fflush(stdout);

  shm_unlink(key);
  int fd = shm_open(key, O_RDWR | O_CREAT | O_TRUNC, 0666);
  if (fd == -1) {
      fprintf(stderr, "mmap_init error shm_open with errno(%s)\n", strerror(errno));
      exit(0);
  }

  if (ftruncate(fd, shm_size) == -1) {
      fprintf(stderr, "mmap_init error ftruncate: errno = %d, shm_size = %ld \n", errno, shm_size);
      perror("ftruncate");
      close(fd);
      exit(0);
  }

  void *shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_POPULATE, fd, 0);
  if (MAP_FAILED == shm_base_addr) {
      fprintf(stderr, "mmap_init error mmap %s size %ld\n", key, shm_size);
      exit(0);
  }

#ifdef LOCK_PAGES
    // Lock the memory pages into RAM
    if (mlock(shm_base_addr, shm_size) != 0) {
        // Err, but not fatal
        fprintf(stderr, "Error: Unable to pin pages.\n");
    }
#endif

  return shm_base_addr;
}


static void *shm_create_region_data_seg(char* base, const char *key, size_t shm_size) {
    if (shm_size == 0) return NULL;

    shm_unlink(key);
    int fd = shm_open(key, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        fprintf(stderr, "mmap_init data_seg error shm_open with errno(%s)\n", strerror(errno));
        exit(1);
    }

    /* Write all current contents of the data segment to the file */
    FILE *fp = fdopen(fd, "wb");
    size_t ret = fwrite(base, shm_size, 1, fp);

    if (ret == 0) {
        fprintf(stderr, "mmap_init error fwrite\n");
        exit(1);
    }

    if (ftruncate(fd, shm_size) == -1) {
        fprintf(stderr, "mmap_init error ftruncate with errno(%s)\n", strerror(errno));
        exit(1);
    }

    void *shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_POPULATE, fd, 0);
    if (MAP_FAILED == shm_base_addr) {
        fprintf(stderr, "mmap_init error mmap %s size %ld\n", key, shm_size);
        exit(1);
    }

#ifdef LOCK_PAGES
    // Lock the memory pages into RAM
    if (mlock(shm_base_addr, shm_size) != 0) {
        // Err, but not fatal
        fprintf(stderr, "shm_create_region_data_seg: Error: Unable to pin pages.\n");
    }
#endif

    fclose(fp);

    return shm_base_addr;
}


static void *shm_attach_region(char* base, const char *key, unsigned int shm_size) {
  if (shm_size == 0) return NULL;

  int fd = shm_open(key, O_RDWR, 0);
  if (fd == -1) {
      fprintf(stderr, "mmap_init error shm_open\n");
      exit(0);
  }
  void *shm_base_addr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
  if (MAP_FAILED == shm_base_addr) {
      fprintf(stderr, "mmap_init error mmap %s  size %d\n", key, shm_size);
      exit(0);
  }

#ifdef LOCK_PAGES
    // Lock the memory pages into RAM
    if (mlock(shm_base_addr, shm_size) != 0) {
        // Err, but not fatal
        fprintf(stderr, "shm_attach_region: Error: Unable to pin pages.\n");
    }
#endif

  return shm_base_addr;
}


struct share_info_t {
    size_t data_len;
    size_t data_off;
    size_t heap_len;
    size_t heap_off;
};

struct shmem_transport_mmap_peer_info_t *shmem_transport_mmap_peers = NULL;
static struct share_info_t my_info;

#define FIND_BASE(ptr, page_size) ((char*) (((uintptr_t) ptr / page_size) * page_size))
#define FIND_LEN(ptr, len, page_size) ((((char*) ptr - FIND_BASE(ptr, page_size) + len - 1) / \
                                        page_size + 1) * page_size)

// bman
#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)

#define ENV_VAR "PERFMON_FILE_PATH"
#define MAX_STRING_LENGTH 1024

// Struct to store the command and constants
typedef struct {
    char command[1024];
    int  constant[NUM_CONSTANTS];  // Array to hold 4 numerical constants (integers)
} PerfmonCommand;

// Helper function to trim leading and trailing spaces
static char * trim(char* str) 
{
    char* end;

    // Trim leading spaces
    while (isspace((unsigned char)*str)) str++;

    // Trim trailing spaces
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Null-terminate the string
    *(end + 1) = '\0';

    return str;
}

// Lookup function to map string constants to actual integer values
int getConstantValue(const char* raw_constant) 
{
    char* constant = trim(strdup(raw_constant));

    if (strcmp(constant, "PERF_TYPE_HW_CACHE") == 0) {
        return PERF_TYPE_HW_CACHE;
    } else if (strcmp(constant, "PERF_COUNT_HW_CACHE_L1D") == 0) {
        return PERF_COUNT_HW_CACHE_L1D;
    } else if (strcmp(constant, "PERF_COUNT_HW_CACHE_OP_READ") == 0) {
        return PERF_COUNT_HW_CACHE_OP_READ;
    } else if (strcmp(constant, "PERF_COUNT_HW_CACHE_OP_WRITE") == 0) {
        return PERF_COUNT_HW_CACHE_OP_WRITE;
    } else if (strcmp(constant, "PERF_COUNT_HW_CACHE_RESULT_MISS") == 0) {
        return PERF_COUNT_HW_CACHE_RESULT_MISS;
    } else if (strcmp(constant, "PERF_COUNT_HW_CACHE_RESULT_ACCESS") == 0) {
        return PERF_COUNT_HW_CACHE_RESULT_ACCESS;
    } else {
        fprintf(stderr, "Error: getConstantValue(): Unable to decode %s into a constant. \n", constant);
        free (constant);
        exit(EXIT_FAILURE);
    }
}

// Function to read the commands and constants from the file
PerfmonCommand commands[NUM_EVENTS_MAX];
static PerfmonCommand* readPerfmonCommandsFromFile(const char* filePath, size_t* count) 
{
    FILE* inputFile = fopen(filePath, "r");
    if (!inputFile) {
        fprintf(stderr, "Error: Could not open file '%s'\n", filePath);
        return NULL;  // Return NULL if file cannot be opened
    }

    size_t capacity = 0;
    *count = 0;
    char buffer[MAX_STRING_LENGTH];

    while (fgets(buffer, sizeof(buffer), inputFile)) 
    {
        buffer[strcspn(buffer, "\n")] = '\0';  // Remove newline character

        // Ignore blank lines
        if (buffer[0] == '\0') {
            continue;
        }

        // Extract the command (first token)
        char* first_token = strtok(buffer, ",");
        if (!first_token) {
            fprintf(stderr, "Error: Malformed line in file\n");
            continue;
        }
        //if (shmem_internal_my_pe == 0) {printf("\nfirst_token = %s. capacity = %d, *count = %ld \n", first_token, capacity, *count); fflush(stdout);}             // is corect

        // Initialize variables to hold the separated values
        char* constants[NUM_CONSTANTS];  // Array to hold the constants as strings

        // Extract the remaining 4 tokens (constants)
        int i = 0;
        while (i < NUM_CONSTANTS && (constants[i] = strtok(NULL, ",")) != NULL) {
            //if (shmem_internal_my_pe == 0) {printf("constants[%d] = %s \n", i, constants[i]); fflush(stdout);}
            i++;
        }

        // Ensure there are exactly 4 constants, fill with empty strings if necessary
        while (i < NUM_CONSTANTS) {
            constants[i++] = strdup("");  // Use strdup to avoid uninitialized pointers
            printf("constants2[%d] = %s \n", i, constants[i]); fflush(stdout);          // not seen
        }

        // Copy event name string
        //if (shmem_internal_my_pe == 0) {printf("Copying event name %s to %p \n", first_token, &(commands[*count].command)); fflush(stdout);}
        strcpy(commands[*count].command, first_token);
        //if (shmem_internal_my_pe == 0) {printf("Read-Back: %s \n", commands[*count].command); fflush(stdout);}                           // correct

        // Convert constants to integers using the lookup function
        for (int j = 0; j < NUM_CONSTANTS; j++) 
        {
            //if (shmem_internal_my_pe == 0) {printf("Converting constant %s to value %d \n", constants[j], getConstantValue(constants[j])); fflush(stdout);}

            commands[*count].constant[j] = getConstantValue(constants[j]);
            if (commands[*count].constant[j] == -1) {
                fprintf(stderr, "Error: Unrecognized constant '%s'\n", constants[j]);
                fclose(inputFile);
                return NULL;  // Return NULL if any constant is unrecognized
            }
        }
        //if (shmem_internal_my_pe == 0) {printf("->commands[*count=%ld].command = %s \n", *count, commands[*count].command); fflush(stdout);}           // correct
        //if (shmem_internal_my_pe == 0) {printf("\n");}
        (*count)++;
    }

    fclose(inputFile);
    return commands;
}

// Use the 0th event (only really supporting one anyhow) to roughly compensate for overhead related to PERFMON calls in the critical path.
int calibrate_perfmon()
{
    volatile char temp;
    long long start_counter;
    long long end_counter;

    ioctl(perf_event_fd[0], PERF_EVENT_IOC_DISABLE, 0);
    ioctl(perf_event_fd[0], PERF_EVENT_IOC_RESET, 0);       // set counter to 0
    ioctl(perf_event_fd[0], PERF_EVENT_IOC_ENABLE, 0);      // start counter
    read(perf_event_fd[0], &(start_counter), sizeof(start_counter));
    ioctl(perf_event_fd[0], PERF_EVENT_IOC_DISABLE, 0);     // include this ioctl front porch in the measurement
    read(perf_event_fd[0], &(end_counter), sizeof(end_counter));
    return (end_counter - start_counter);
}
#endif


int shmem_transport_mmap_init(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    char *base;
    size_t len;
    int ret;
    char key_prefix[MPIDI_OFI_SHMGR_NAME_MAXLEN-10];
    char key[MPIDI_OFI_SHMGR_NAME_MAXLEN];

    /* setup data region */
    base = FIND_BASE(shmem_internal_data_base, page_size);
    len = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, page_size);


#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)
    size_t count;
    const char* filePath = getenv(ENV_VAR);
    if (!filePath) {
        fprintf(stderr, "Error: Environment variable %s is not set\n", ENV_VAR);
        return EXIT_FAILURE;
    }

    // Read data from file that contains the counter name as well as certain config params 
    PerfmonCommand* counter_list = readPerfmonCommandsFromFile(filePath, &count);
    if (!counter_list) {
        fprintf(stderr, "ERROR: unable to process perfrmon file.\n");
        exit(EXIT_FAILURE);
    }

    if (count > 1) {
        printf("WARNING: Read more than one event. BKM is to use a single event per run for max accuracy!\n");
        sleep(2);
    }
    if (count == 0) {
        fprintf(stderr, "Error: nothing read from file. \n");
        exit(EXIT_FAILURE);
    }
    memset(eventReadBuffer, 0, sizeof(eventReadBuffer));
    memset(perf_event, 0, sizeof(perf_event));

    // Dump
    for (size_t i = 0; i < count; i++) 
    {
        if (shmem_internal_my_pe == 0) {printf("Command: %s\n", counter_list[i].command); fflush(stdout);}
        for (int j = 0; j < NUM_CONSTANTS; j++)
        {
            if (shmem_internal_my_pe == 0) {printf("  Constant[%d]: %d\n", j, counter_list[i].constant[j]); fflush(stdout);}
        }
    }

    for (size_t line = 0; line < count; line++) 
    {
        perf_event[line].type           = counter_list[line].constant[0];
        perf_event[line].size           = sizeof(struct perf_event_attr);
        perf_event[line].config         = (counter_list[line].constant[1]) | (counter_list[line].constant[2] << 8) | (counter_list[line].constant[3] << 16);
        perf_event[line].disabled       = 1; // Start the event disabled
        perf_event[line].exclude_kernel = 1; // Exclude kernel events
        perf_event[line].exclude_hv     = 1; // Exclude Hypervisor events

        // Open perf events
        perf_event_fd[line] = syscall(__NR_perf_event_open, &perf_event[line], 0, -1, -1, 0);
        if (perf_event_fd[line] == -1) 
        {
            fprintf(stderr, "Error opening perf event(%ld) %s.\n", line, commands[line].command);         // <=== get this now: Error opening perf event: No such file or directory
            // Track the non-working counters in a bitmask (redundent)
            non_working_events = non_working_events | (1 << line);
        }
        else {
            printf("Sucessfully opened event handle\n");
            // Mark as working by clearing our bit
            non_working_events = non_working_events & ~(1 << line);     
        }
    }   

    // Update global count of events
    eventCount = count;

    // Calibrate
    perfmon_overhead = calibrate_perfmon();
#endif


    // bman
    //printf("==>shmem_transport_mmap_init(void): data len = %ld \n", len); fflush(stdout);
    //
    // /bman  
    
    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 1);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-data", key_prefix);
    void* myaddr_data = shm_create_region_data_seg(base, key, len);
    if (myaddr_data == NULL) return 1;

    my_info.data_off = (char*) shmem_internal_data_base - (char*) base;
    my_info.data_len = len;

    /* setup heap region */
    base = FIND_BASE(shmem_internal_heap_base, page_size);
    len  = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, page_size);

    // bman
    //printf("==>shmem_transport_mmap_init(void): heap len = %ld \n", len); fflush(stdout);
    //
    
    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 2);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-heap", key_prefix);
    void* myaddr_heap = shm_create_region(base, key, len);
    if (myaddr_heap == NULL) return 1;

    my_info.heap_off = (char*) shmem_internal_heap_base - (char*) base;
    my_info.heap_len = len;

    ret = shmem_runtime_put("mmap-segids", &my_info, sizeof(struct share_info_t));
    if (0 != ret) {
        RETURN_ERROR_MSG("runtime_put failed: %d\n", ret);
        return 1;
    }

    return 0;
}


int
shmem_transport_mmap_startup(void)
{
    int ret, peer_num, num_on_node;
    char errmsg[256];
    struct share_info_t info;
    //struct mmap_addr addr;
    long page_size = sysconf(_SC_PAGESIZE);

    num_on_node = shmem_runtime_get_node_size();

    // bman
    cnt = aligned_cnt = unaligned_cnt = aligned_src_cnt = total_count = buff_source_size_largerThan64_aligned = buff_adjusted_dest_size_largerThan64_aligned = buff_source_64_aligned = buff_adjusted_dest_64_aligned = aligned_dest_cnt = buff_source_size_aligned = buff_adjusted_dest_size_aligned = 0;
    //

    /* allocate space for local peers */
    shmem_transport_mmap_peers = calloc(num_on_node,
                                         sizeof(struct shmem_transport_mmap_peer_info_t));
    if (NULL == shmem_transport_mmap_peers) return 1;

    /* get local peer info and map into our address space ... */
    for (int i = 0 ; i < shmem_internal_num_pes; ++i) {
        peer_num = shmem_runtime_get_node_rank(i);
        if (-1 == peer_num) continue;

        if (shmem_internal_my_pe == i) {
            shmem_transport_mmap_peers[peer_num].data_ptr =
                shmem_internal_data_base;
            shmem_transport_mmap_peers[peer_num].heap_ptr =
                shmem_internal_heap_base;
        } else {
            ret = shmem_runtime_get(i, "mmap-segids", &info, sizeof(struct share_info_t));
            if (0 != ret) {
                RETURN_ERROR_MSG("runtime_get failed: %d\n", ret);
                return 1;
            }

            char key_prefix[MPIDI_OFI_SHMGR_NAME_MAXLEN-10];
            char key[MPIDI_OFI_SHMGR_NAME_MAXLEN];
            int len = 0;

	    /* Attach data segment to neighbors: */
            len  = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, page_size);
            shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, i, 1);
            snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-data", key_prefix);
            shmem_transport_mmap_peers[peer_num].data_attach_ptr = shm_attach_region(NULL, key, len);

            if (shmem_transport_mmap_peers[peer_num].data_attach_ptr == NULL) {
                RETURN_ERROR_MSG("could not get data segment: %s\n",
                                 shmem_util_strerror(errno, errmsg, 256));
                return 1;
            }
            shmem_transport_mmap_peers[peer_num].data_ptr =
                (char*) shmem_transport_mmap_peers[peer_num].data_attach_ptr + info.data_off;

            /* Attach heap segment to neighbors: */
            len  = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, page_size);
            shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, i, 2);
            snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-heap", key_prefix);
            shmem_transport_mmap_peers[peer_num].heap_attach_ptr = shm_attach_region(NULL, key, len);

            if (shmem_transport_mmap_peers[peer_num].heap_attach_ptr == NULL) {
                RETURN_ERROR_MSG("could not get heap segment: %s\n",
                                 shmem_util_strerror(errno, errmsg, 256));
                return 1;
            }
            shmem_transport_mmap_peers[peer_num].heap_ptr =
                (char*) shmem_transport_mmap_peers[peer_num].heap_attach_ptr + info.heap_off;
        }
    }

    return 0;
}


int
shmem_transport_mmap_fini(void)
{
    int i, peer_num, ret;
    char errmsg[256];
    size_t data_len, heap_len;
    char key_prefix[MPIDI_OFI_SHMGR_NAME_MAXLEN-10];
    char key[MPIDI_OFI_SHMGR_NAME_MAXLEN];
    long page_size = sysconf(_SC_PAGESIZE);

#ifdef BMAN_TRACK_ALIGNMENT
    // bman hack
    printf("\n===>For 64B: Total cnt = %d, Both aligned_cnt = %d, aligned_src_cnt = %d, aligned_dest_cnt = %d \n===>For all sizes: total_count = %d, #buff_source_size_aligned = %d (%.4f%), #buff_adjusted_dest_size_aligned = %d(%.4f%) \n                   buff_source_64_aligned = %d(%.4f%), buff_adjusted_dest_64_aligned = %d(%.4f%)\n                   buff_source_size_largerThan64_aligned = %d(%.4f%), buff_adjusted_dest_size_largerThan64_aligned = %d(%.4f%)\n", cnt, aligned_cnt, aligned_src_cnt, aligned_dest_cnt, total_count, buff_source_size_aligned, (float)buff_source_size_aligned / total_count * 100.0, buff_adjusted_dest_size_aligned, (float)buff_adjusted_dest_size_aligned / total_count * 100.0, buff_source_64_aligned, (float)buff_source_64_aligned / total_count * 100.0, buff_adjusted_dest_64_aligned, (float)buff_adjusted_dest_64_aligned / total_count * 100.0, buff_source_size_largerThan64_aligned, (float)buff_source_size_largerThan64_aligned / total_count * 100.0, buff_adjusted_dest_size_largerThan64_aligned, (float)buff_adjusted_dest_size_largerThan64_aligned / total_count * 100.0);
    fflush(stdout);
#endif

#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)
    // Print out lockstep - i.e. present the samples temporally aligned
    int running_sum[MAX_EVENTS] = {0};
    //if (0 == shmem_internal_my_pe) 
    {
        printf("[%d] fini: eventCount=%d, diff_count=%d, NUM_MEASUREMENTS=%d, perfmon_overhead=%d\n", shmem_internal_my_pe,eventCount,diff_count,NUM_MEASUREMENTS,perfmon_overhead); fflush(stdout);

        // Average and (optionally) Dump raw data
        for (int y=0; y < diff_count; y++) {
            for (int x=0; x < eventCount; x++) {
                if (non_working_events & (1 << x))
                {
                    static bool once = false;
                    if (false == once) {
                        printf("[%d]Event %s: Non-Fuctional.\n", shmem_internal_my_pe, commands[x].command);
                        printf("->non_working_events & (non_working_events<<%d)=%d\n", x, non_working_events & (non_working_events<<x)); fflush(stdout);
                        once = true;
                    }
                }
                else if (666 != eventReadBuffer[x].tdiff[y]) 
                {
                    running_sum[x] += (eventReadBuffer[x].tdiff[y] - perfmon_overhead);
                    //printf("Event %s (adjusted for overhead): %lld\n", commands[x].command, eventReadBuffer[x].tdiff[y] - perfmon_overhead);    // *Adjust for overhead
                }
            }
            //printf("----------------\n");
        }
        
        // Compute and print averages
        printf("\n[%d]****Averages****\n", shmem_internal_my_pe); fflush(stdout);
        for (int ev = 0; ev < eventCount; ev++) 
        {
            int avg = (diff_count > 0) ? running_sum[ev] / diff_count : 666;
            printf("[%d] Event %s (adjusted for ovherhead): avg = %d\n", shmem_internal_my_pe, commands[ev].command, avg); fflush(stdout);
        }
    }
#endif

    data_len = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, page_size);
    heap_len = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, page_size);

    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 1);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-data", key_prefix);

    ret = shm_unlink(key);
    if (ret != 0) {
        RETURN_ERROR_MSG("could not get data segment: %s\n", \
                         shmem_util_strerror(errno, errmsg, 256));
    }

    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 2);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-heap", key_prefix);

    ret = shm_unlink(key);
    if (ret != 0) {
        RETURN_ERROR_MSG("could not get heap segment: %s\n", \
                         shmem_util_strerror(errno, errmsg, 256));
    }

    if (NULL != shmem_transport_mmap_peers) {
        for (i = 0 ; i < shmem_internal_num_pes; ++i) {
            peer_num = shmem_runtime_get_node_rank(i);
            if (-1 == peer_num) continue;
            if (shmem_internal_my_pe == i) continue;

            if (NULL != shmem_transport_mmap_peers[peer_num].data_attach_ptr) {
                munmap(shmem_transport_mmap_peers[peer_num].data_attach_ptr, data_len);
            }

            if (NULL != shmem_transport_mmap_peers[peer_num].heap_attach_ptr) {
                munmap(shmem_transport_mmap_peers[peer_num].heap_attach_ptr, heap_len);
            }
        }
        free(shmem_transport_mmap_peers);
    }

    return 0;
}
