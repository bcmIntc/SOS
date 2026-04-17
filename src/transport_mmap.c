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
#ifdef __linux__
 #include <mntent.h>
 #include <sys/vfs.h>
#endif

#define SHMEM_INTERNAL_INCLUDE
#include "shmem.h"
#include "shmem_internal.h"
#include "shmem_comm.h"
#include "runtime.h"
#include "transport_mmap.h"

#define MPIDI_OFI_SHMGR_NAME_MAXLEN (128)
#define MPIDI_OFI_SHMGR_NAME_PREFIX "/sos_shm_mmap_area"


// bman
//#define HUGEPAGE_SIZE_THRESHOLD sysconf(_SC_PAGESIZE)                                 // R: fails mmap() alignment pre-check. Cannot map < hugePageSize. We could create a huge-page allocator. Let's not.
#define HUGEPAGE_SIZE_THRESHOLD shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE			// ==2KiB by default

#ifndef FLOOR
 #define FLOOR(a,b)      ((uint64_t)(a) - ( ((uint64_t)(a)) % (uint64_t)(b)))
#endif
#ifndef CEILING
 #define CEILING(a,b)    ((uint64_t)(a) <= 0LL ? 0 : (FLOOR((a)-1,b) + (b)))
#endif

#ifdef USE_TSX_ATOMIC
 volatile int takenCount=666;
 volatile int totalCount=666;
#endif

#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)

 SHOULD_BE_DISABLED2;

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

static int find_hugepage_dir(size_t page_size, char **directory)
{
    int ret = -1;
    struct statfs pg_size;
    struct mntent *mntent;
    FILE *fd;
    char *path;


    if (!directory || !page_size) {
        return ret;
    }

    fd = setmntent ("/proc/mounts", "r");
    if (fd == NULL) {
		printf("ERROR: find_hugepage_dir: setmntent failed \n");
        return ret;
    }

    while ((mntent = getmntent(fd)) != NULL) 
	{
        if (strcmp (mntent->mnt_type, "hugetlbfs") != 0) {
            continue;
        }

        path = mntent->mnt_dir;
        if (statfs(path, &pg_size) == 0) 
		{
            if ((size_t) pg_size.f_bsize == page_size) 
			{
                *directory = strdup(path);
                ret = 0;
                break;
            }
        }
    }

	printf("-find_hugepage_dir: ret = %d, mntent->mnt_type = %s, *directory=%s \n", ret, mntent->mnt_type, *directory);

    endmntent(fd);
    return ret;
}

// creates a shared region for symmetric heap
static void *shm_create_region(char* base, const char *key, size_t shm_size) {
  if (shm_size == 0) return NULL;

  shm_unlink(key);

  void *shm_base_addr = NULL;    
  int mypid = getpid();
  int fd = 0;
  if ((shm_size > HUGEPAGE_SIZE_THRESHOLD) && shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES) 
  {
    printf("[%d:%d] ==> +shm_create_region: Using huge pages for my Heap segment. shm_size = %lu \n", mypid, shmem_my_pe(), shm_size); // shm_size = 5,369,757,696

    /* check what /proc/mounts has for explicit huge page support */
    char *directory = NULL;
    char *file_name = NULL;
    if (find_hugepage_dir(shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE, &directory) == 0)
    {
		printf("find_hugepage_dir succeeded\n");

        size_t len = strlen(directory) + strlen(key) + 2;   // 2 for: '/' + '\0'
        file_name = malloc(len);
        sprintf(file_name, "%s%s", directory, key);

        fd = open(file_name, O_CREAT | O_RDWR, 0755);
        if (fd < 0) {
            RAISE_WARN_STR("file open failed, cannot use huge pages");		// <== bman: here
			printf("Failed to open: file_name=%s, err=%s \n", file_name, strerror(errno));			// F: Failed to open: file_name=/dev/hugepages/sos_shm_mmap_area-1-2-heap
            fd = 0;
            exit(1);
        }
        else
        {
            /* have to round up by the pagesize being used */
            shm_size = CEILING(shm_size, shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE);

            // DBG
            printf("[%d:%d] ==> +shm_create_region: Using HUGE_PAGES for my Heap segment. shm_size = %lu \n", mypid, shmem_my_pe(), shm_size);

            if (ftruncate(fd, shm_size) == -1) {
                  fprintf(stderr, "shm_create_region: error ftruncate: errno = %d, shm_size = %ld \n", errno, shm_size);
                  perror("ftruncate");
                  close(fd);
                  exit(0);
            }
        }
    }
	printf("Yuge: Calling mmap(%p, %lu, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_HUGETLB, fd, 0 \n", base, shm_size); fflush(stdout);
    shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_HUGETLB, fd, 0);
  } 
  else 
  {
      printf("[%d:%d] ==> +shm_create_region: Using normal pages for my Heap segment. shm_size = %lu \n", mypid, shmem_my_pe(), shm_size); // shm_size = 5,369,757,696
      fd = shm_open(key, O_RDWR | O_CREAT | O_TRUNC, 0666);
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
	  printf("Normal: Calling mmap(%p, %lu, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0 \n", base, shm_size); fflush(stdout);
      shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
  }

  //void *shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_POPULATE, fd, 0);
  if (MAP_FAILED == shm_base_addr) {
      fprintf(stderr, "shm_create_region: error mmap: %s, size: %ld\n", key, shm_size);
      perror("shm_create_region mmap");											// <== HERE now after using sudo to chmod /dev/hugepages
      exit(0);
  }

#if defined(LOCK_PAGES)
    // Lock the memory pages into RAM
    if (mlock(shm_base_addr, shm_size) != 0) {
        fprintf(stderr, "shm_create_region(): Error: Unable to pin pages.\n");
        munmap(shm_base_addr, shm_size);
        shmem_finalize();
        perror("mlock-shm_create_region");
        exit(1);
    }
#elif defined(FAULT_PAGES_MANUALLY)
    // Fault in pages manually
    long page_size = sysconf(_SC_PAGESIZE);                     // bman: BUG: this needs to determine the pagesize of the mapping
    for (size_t i = 0; i < shm_size; i += page_size) {
        ((char *)shm_base_addr)[i] = 0;
    }
#endif

  //printf("[%d] ==> -shm_create_region: returning shm_base_addr = %p \n", shmem_my_pe(), shm_base_addr);

  close(fd);            // we don't need it after mmap
  return shm_base_addr;
}


static void *shm_create_region_data_seg(char* base, const char *key, size_t shm_size) 
{
  if (shm_size == 0) return NULL;
  int fd = 0;
  FILE *fp = NULL;
    
  void *shm_base_addr;
  if ((shm_size > HUGEPAGE_SIZE_THRESHOLD) && shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES)
  {
    /* check what /proc/mounts has for explicit huge page support */
    char *directory = NULL;
    char *file_name = NULL;
    if (find_hugepage_dir(shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE, &directory) == 0)
    {
        size_t len = strlen(directory) + strlen(key) + 2;   // 2 for: '/' + '\0'
        file_name = malloc(len);
        if (file_name)
        {
            sprintf(file_name, "%s%s", directory, key);
            fd = open(file_name, O_CREAT | O_RDWR, 0666);
            if (fd < 0) {
                RAISE_WARN_STR("file open failed, cannot use huge pages");
                perror("shm_create_region_data_seg: open().");
                exit(1);
            }
            else
            {
                /* Write all current contents of the data segment to the file */
                /* have to round up by the pagesize being used */
                shm_size = CEILING(shm_size, shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE);
        
                // DBG
                printf("[%d:%d] ==> +shm_create_region_data_seg: Using HUGE_PAGES for my Data segment. shm_size = %lu \n", getpid(), shmem_my_pe(), shm_size);

                if (ftruncate(fd, shm_size) == -1) {
                    fprintf(stderr, "shm_create_region_data_seg: huge pages: error ftruncate with errno(%s)\n", strerror(errno));
                    exit(1);
                }
                if (((uintptr_t)base % shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE) != 0) {
                    fprintf(stderr, "[%d] ERROR: shm_create_region_data_seg: alignment check on base failed. base = %p, shmem_internal_data_base = %p\n", shmem_my_pe(), base, shmem_internal_data_base); 
                    fflush(stdout); 
                    exit(1);
                }
                shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_HUGETLB, fd, 0);
                if (shm_base_addr == MAP_FAILED) {
                    perror("shm_create_region_data_seg:: mmap failed");
                    exit(1);  // DO NOT call memcpy if mmap failed!
                }

                // Copy section data
                memcpy(shm_base_addr, base, shm_size);            
            }
          }
          else
          {
              perror("file_name malloc");
              exit(1);
          }
    }
    else 
    {
        fprintf(stderr, "shm_create_region_data_seg: huge pages: Unable to find huge page mount point. \n");
        exit(1);
    }
  } 
  else
  {
        shm_unlink(key);

        // DBG
        printf("[%d:%d] ==> +shm_create_region_data_seg: Using normal pages for my Data segment. shm_size = %lu \n", getpid(), shmem_my_pe(), shm_size);

        fd = shm_open(key, O_RDWR | O_CREAT | O_TRUNC, 0666);
        if (fd == -1) {
            fprintf(stderr, "shm_create_region_data_seg: data_seg error shm_open with errno(%s)\n", strerror(errno));
            exit(1);
        }
        /* Write all current contents of the data segment to the file */
        fp = fdopen(fd, "wb");
        size_t ret = fwrite(base, shm_size, 1, fp);
        if (ret == 0) {
            fprintf(stderr, "shm_create_region_data_seg: error fwrite\n");
            exit(1);
        }
        if (ftruncate(fd, shm_size) == -1) {
            fprintf(stderr, "shm_create_region_data_seg: error ftruncate with errno(%s)\n", strerror(errno));
            exit(1);
        }

        shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
  }

  // OG:
  //void *shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_POPULATE, fd, 0);
  //void *shm_base_addr = mmap(base, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);

  if (MAP_FAILED == shm_base_addr) {
      fprintf(stderr, "shm_create_region_data_seg error: mmap: %s, size = %ld\n", key, shm_size);
      exit(1);
  }

#if defined(LOCK_PAGES)
    // Lock the memory pages into RAM
    if (mlock(shm_base_addr, shm_size) != 0) {
        fprintf(stderr, "shm_create_region_data_seg(): Error: Unable to pin pages.\n");
        munmap(shm_base_addr, shm_size);
        shmem_finalize();
        perror("mlock-shm_create_region_data_seg");
        exit(1);
    }
#elif defined(FAULT_PAGES_MANUALLY)
    long page_size = sysconf(_SC_PAGESIZE);
    // Fault in pages manually
    for (size_t i = 0; i < shm_size; i += page_size) {
        ((char *)shm_base_addr)[i] = 0;    
    }
#endif

    fclose(fp);
    close(fd);            // we don't need it after mmap
    
    return shm_base_addr;
}


static void *shm_attach_region(char* base, const char *key, size_t shm_size) 
{
  if (shm_size == 0) return NULL;
  int fd = 0;

  void *shm_base_addr;
  if ((shm_size > HUGEPAGE_SIZE_THRESHOLD) && shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES)
  {
    /* check what /proc/mounts has for explicit huge page support */
    char *directory = NULL;
    char *file_name = NULL;
    if (find_hugepage_dir(shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE, &directory) == 0)
    {
        // DBG
        printf("[%d:%d] ==> +shm_attach_region: Using HUGE_PAGES. Process Neighbor: key = %s, shm_size = %lu \n", getpid(), shmem_my_pe(), key, shm_size); // shm_size = 5,369,757,696

        size_t len = strlen(directory) + strlen(key) + 2;   // 2 for: '/' + '\0'
        file_name = malloc(len);
        if (file_name)
        {
            sprintf(file_name, "%s%s", directory, key);

            fd = open(file_name, O_CREAT | O_RDWR, 0755);
            if (fd < 0) {
                RAISE_WARN_STR("file open failed, cannot use huge pages");
                fd = 0;
                exit(1);
            }
            else
            {
                /* have to round up by the pagesize being used */
                shm_size = CEILING(shm_size, shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE);
            }
        }
    }
    shm_base_addr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_HUGETLB, fd, 0);
  }
  else
  {
      // DBG
      printf("[%d:%d] ==> +shm_attach_region: Using normal pages. Process Neighbor: key = %s, shm_size = %lu \n", getpid(), shmem_my_pe(), key, shm_size); // shm_size = 5,369,757,696

      fd = shm_open(key, O_RDWR, 0);                            // <== bman: this is the shm file of a neighbor, not ours.
      if (fd == -1) {
          fprintf(stderr, "mmap_init error shm_open\n");
          exit(0);
      }
      shm_base_addr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  }

  // OG:
  //void *shm_base_addr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
  //void *shm_base_addr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (MAP_FAILED == shm_base_addr) {
      fprintf(stderr, "shm_attach_region error. mmap: %s, size = %lu\n", key, shm_size);
      exit(0);
  }

#if defined(LOCK_PAGES)
    // Lock the memory pages into RAM
    if (mlock(shm_base_addr, shm_size) != 0) {
        fprintf(stderr, "shm_attach_region: Error: Unable to pin pages.\n");
        munmap(shm_base_addr, shm_size);
        shmem_finalize();
        perror("mlock-shm_attach_region");
        exit(1);
    }
#elif defined(FAULT_PAGES_MANUALLY)
    long page_size = sysconf(_SC_PAGESIZE);
    // Fault in pages manually
    for (size_t i = 0; i < shm_size; i += page_size) {
        ((char *)shm_base_addr)[i] = 0;
    }
#endif

  close(fd);            // we don't need it after mmap
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

  SHOULD_NOT_BE_ENABLED3;

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
            //printf("constants2[%d] = %s \n", i, constants[i]); fflush(stdout);          // not seen
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

    //size_t temp = (shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES == 1) ? shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE : page_size;
    size_t temp = page_size;

    base = FIND_BASE(shmem_internal_data_base, temp);           // big? if using 4k pages all over, and then we have this large page, bad offset adjust?
    //printf("[%d] ==> shmem_transport_mmap_init(): temp = %lu\n", shmem_my_pe(), temp);


    //temp = (shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES == 1) ? shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE : page_size;
    len  = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, temp);

    // bman
    //printf("[%d] ==>shmem_transport_mmap_init(): shmem_internal_data_base = %p -vs- base = %p, shmem_internal_data_length = %ld -vs- len = %ld, temp = %lu \n", shmem_my_pe(), shmem_internal_data_base, base, shmem_internal_data_length, len, temp); fflush(stdout);
    // 0x4261c0 -vs- base = 0x400000, shmem_internal_data_length = 5536 -vs- len = 2097152


#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)
    FEATURE_SHOULD_BE_DISABLED4;

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


    // /bman  
    
    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 1);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-data", key_prefix);
    void* myaddr_data = shm_create_region_data_seg(base, key, len);
    if (myaddr_data == NULL) return 1;

    my_info.data_off = (char*) shmem_internal_data_base - (char*) base;
    my_info.data_len = len;

    /* setup heap region */
    temp = (shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES==1) ? shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE : page_size;
    base = FIND_BASE(shmem_internal_heap_base, temp);
    len  = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, temp);

    // bman
    //printf("==>shmem_transport_mmap_init(void): Calling shm_create_region(len = heap len = %ld) \n", len); fflush(stdout);
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


static void unlink_my_regions(void)
{
    char key_prefix[MPIDI_OFI_SHMGR_NAME_MAXLEN-10];
    char key[MPIDI_OFI_SHMGR_NAME_MAXLEN];
    long page_size = sysconf(_SC_PAGESIZE);
    size_t hp_size = shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE;
    size_t temp;
    char *directory = NULL;
    char *file_name = NULL;

    /* data segment */
    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 1);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-data", key_prefix);

    temp = shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES ? hp_size : page_size;
    size_t data_len = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, temp);

    if ((data_len > HUGEPAGE_SIZE_THRESHOLD) && shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES) {
        if (find_hugepage_dir(hp_size, &directory) == 0) {
            file_name = malloc(strlen(directory) + strlen(key) + 2);
            if (file_name) {
                sprintf(file_name, "%s%s", directory, key);
                unlink(file_name);
                free(file_name);
            }
            free(directory);
        }
    } else {
        shm_unlink(key);
    }

    /* heap segment */
    shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, shmem_internal_my_pe, 2);
    snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-heap", key_prefix);

    size_t heap_len = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, temp);

    if ((heap_len > HUGEPAGE_SIZE_THRESHOLD) && shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES) {
        directory = NULL;
        if (find_hugepage_dir(hp_size, &directory) == 0) {
            file_name = malloc(strlen(directory) + strlen(key) + 2);
            if (file_name) {
                sprintf(file_name, "%s%s", directory, key);
                unlink(file_name);
                free(file_name);
            }
            free(directory);
        }
    } else {
        shm_unlink(key);
    }
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
            size_t len = 0;

	    /* Attach data segment to neighbors: */
            size_t temp = (shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES==1) ? shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE : page_size;
            len  = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, temp);
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
            len  = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, temp);
            shm_create_key(key_prefix, MPIDI_OFI_SHMGR_NAME_MAXLEN-10, i, 2);
            snprintf(key, MPIDI_OFI_SHMGR_NAME_MAXLEN, "%s-heap", key_prefix);
            
            // bman
            //printf("==> Calling shm_attach_region(len = %ld) to attach to peer's HEAP shm region.\n", len); fflush(stdout);

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

    /* All peers have now attached to our regions — unlink the filesystem
     * entries so no files are left behind if the job crashes from here on. */
    unlink_my_regions();

    return 0;
}


int
shmem_transport_mmap_fini(void)
{
    int i, peer_num;
    char errmsg[256];
    size_t data_len, heap_len;
    long page_size = sysconf(_SC_PAGESIZE);

#ifdef BMAN_TRACK_ALIGNMENT
    // bman hack
    printf("\n===>For 64B: Total cnt = %d, Both aligned_cnt = %d, aligned_src_cnt = %d, aligned_dest_cnt = %d \n===>For all sizes: total_count = %d, #buff_source_size_aligned = %d (%.4f%), #buff_adjusted_dest_size_aligned = %d(%.4f%) \n                   buff_source_64_aligned = %d(%.4f%), buff_adjusted_dest_64_aligned = %d(%.4f%)\n                   buff_source_size_largerThan64_aligned = %d(%.4f%), buff_adjusted_dest_size_largerThan64_aligned = %d(%.4f%)\n", cnt, aligned_cnt, aligned_src_cnt, aligned_dest_cnt, total_count, buff_source_size_aligned, (float)buff_source_size_aligned / total_count * 100.0, buff_adjusted_dest_size_aligned, (float)buff_adjusted_dest_size_aligned / total_count * 100.0, buff_source_64_aligned, (float)buff_source_64_aligned / total_count * 100.0, buff_adjusted_dest_64_aligned, (float)buff_adjusted_dest_64_aligned / total_count * 100.0, buff_source_size_largerThan64_aligned, (float)buff_source_size_largerThan64_aligned / total_count * 100.0, buff_adjusted_dest_size_largerThan64_aligned, (float)buff_adjusted_dest_size_largerThan64_aligned / total_count * 100.0);
    fflush(stdout);
#endif

#if defined(USE_PERFMON_MMAP) || defined(USE_PERFMON_ATM)
    FEATURE_SHOULB_NOT_BE_ENABLED7;

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

    size_t temp = (shmem_internal_params.SYMMETRIC_HEAP_USE_HUGE_PAGES==1) ? shmem_internal_params.SYMMETRIC_HEAP_PAGE_SIZE : page_size;
    data_len = FIND_LEN(shmem_internal_data_base, shmem_internal_data_length, temp);
    heap_len = FIND_LEN(shmem_internal_heap_base, shmem_internal_heap_length, temp);

    /* Best-effort cleanup in case startup() was never reached (e.g. early
     * init failure). unlink_my_regions() is a no-op if already unlinked. */
    unlink_my_regions();

    if (NULL != shmem_transport_mmap_peers) {
        for (i = 0 ; i < shmem_internal_num_pes; ++i) {
            peer_num = shmem_runtime_get_node_rank(i);
            if (-1 == peer_num) continue;
            if (shmem_internal_my_pe == i) continue;

            if (NULL != shmem_transport_mmap_peers[peer_num].data_attach_ptr) {
                //printf("==> unmapping %lu bytes from peer data region. \n", data_len);
                munmap(shmem_transport_mmap_peers[peer_num].data_attach_ptr, data_len);
            }

            if (NULL != shmem_transport_mmap_peers[peer_num].heap_attach_ptr) {
                //printf("==> unmapping %lu bytes from peer heap region. \n", heap_len);
                munmap(shmem_transport_mmap_peers[peer_num].heap_attach_ptr, heap_len);
            }
        }
        free(shmem_transport_mmap_peers);
    }

    return 0;
}
