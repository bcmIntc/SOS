/* Minimal public API for the local oracle model, never used by libsma. */
#ifndef SOS_QUIET_MODEL_SHMEM_H
#define SOS_QUIET_MODEL_SHMEM_H
#include <stddef.h>
typedef void *shmem_ctx_t;
#define SHMEM_CTX_DEFAULT ((shmem_ctx_t) 0)
#define SHMEM_THREAD_SINGLE 0
int shmem_init_thread(int requested, int *provided);
int shmem_my_pe(void);
int shmem_n_pes(void);
void *shmem_malloc(size_t bytes);
void shmem_free(void *ptr);
void shmem_getmem(void *target, const void *source, size_t bytes, int pe);
void shmem_ctx_putmem(shmem_ctx_t ctx, void *target, const void *source,
                      size_t bytes, int pe);
void shmem_putmem_nbi(void *target, const void *source, size_t bytes, int pe);
void shmem_quiet(void);
void shmem_barrier_all(void);
void shmem_finalize(void);
void shmem_global_exit(int status);
#endif
