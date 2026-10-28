/* Manual watchdog regression driver.  Run with at least two PEs.
 * SHMEM_PROGRESS_TIMEOUT=2 oshrun -n 2 ./watchdog wait
 *   must report PE 0 / shmem_int_wait_until and exit nonzero.
 * SHMEM_PROGRESS_TIMEOUT=2 oshrun -n 2 ./watchdog quiet
 *   must complete despite spending five seconds outside SOS.
 * SHMEM_PROGRESS_TIMEOUT=2 oshrun -n 2 ./watchdog progress
 *   must complete despite taking longer than the timeout overall.
 * SHMEM_PROGRESS_TIMEOUT=2 oshrun -n 2 ./watchdog finalize
 *   must time out on PE 0 while finalizing.
 * SHMEM_PROGRESS_TIMEOUT=2 oshrun -n 2 ./watchdog threads
 *   must time out on PE 0 despite completed calls from another thread.
 * SHMEM_PROGRESS_TIMEOUT=0 oshrun -n 2 ./watchdog wait
 *   must remain blocked (terminate manually).
 * SHMEM_PROGRESS_TIMEOUT=121 oshrun -n 2 ./watchdog idle
 *   must warn/backtrace once per PE after 60.5 seconds, continue running,
 *   rearm after the barrier, warn again, and finalize successfully.
 * SHMEM_PROGRESS_TIMEOUT=120 oshrun -n 2 ./watchdog idle
 *   must finish with no application-idle warning (strict >120-second gate).
 * SHMEM_PROGRESS_TIMEOUT=121 oshrun -n 2 ./watchdog idle-progress
 *   must finish with no idle warning despite running for 130 seconds.
 * SHMEM_PROGRESS_TIMEOUT=121 oshrun -n 2 ./watchdog idle-then-wait
 *   must warn first, then fatally time out PE 0 inside SHMEM.
 * SHMEM_PROGRESS_TIMEOUT=121 oshrun -n 2 ./watchdog idle-finalize
 *   must finalize despite an idle warning blocked on a deliberately full
 *   stderr pipe, then print its completion message to stdout.
 * Repeat with argument checking disabled and SHMEM_BACKTRACE unset.
 */
#include <shmem.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

static int flag;

static void *blocked_thread(void *unused)
{
    (void)unused;
    shmem_int_wait_until(&flag, SHMEM_CMP_NE, 0);
    return NULL;
}

int main(int argc, char **argv)
{
    int provided;
    shmem_init_thread(SHMEM_THREAD_MULTIPLE, &provided);
    if (argc != 2 || shmem_n_pes() < 2) {
        fprintf(stderr, "usage: watchdog {wait|quiet|progress|finalize|threads|"
                "idle|idle-progress|idle-then-wait|idle-finalize}, >=2 PEs\n");
        shmem_global_exit(2);
    }
    shmem_barrier_all();
    if (strcmp(argv[1], "wait") == 0) {
        if (shmem_my_pe() == 0)
            shmem_int_wait_until(&flag, SHMEM_CMP_NE, 0);
        else
            for (;;) sleep(1);
    } else if (strcmp(argv[1], "quiet") == 0) {
        sleep(5);
    } else if (strcmp(argv[1], "idle") == 0) {
        for (int i = 0; i < 2; i++) {
            /* Use nanosleep to tolerate signals/debugger detach interrupting
             * the application sleep without losing the remaining interval. */
            struct timespec delay = {65, 0};
            while (nanosleep(&delay, &delay) != 0) {}
            shmem_barrier_all();
        }
        fprintf(stderr, "Application resumed after idle diagnostics\n");
    } else if (strcmp(argv[1], "idle-progress") == 0) {
        for (int i = 0; i < 130; i++) {
            (void)shmem_my_pe();
            sleep(1);
        }
    } else if (strcmp(argv[1], "idle-finalize") == 0) {
        int log_pipe[2], flags;
        char fill[4096] = {0};
        struct timespec delay = {65, 0};
        if (pipe(log_pipe) != 0)
            shmem_global_exit(2);
        flags = fcntl(log_pipe[1], F_GETFL);
        if (flags < 0 || fcntl(log_pipe[1], F_SETFL, flags | O_NONBLOCK) != 0)
            shmem_global_exit(2);
        while (write(log_pipe[1], fill, sizeof(fill)) > 0) {}
        if (errno != EAGAIN ||
            fcntl(log_pipe[1], F_SETFL, flags) != 0 ||
            dup2(log_pipe[1], STDERR_FILENO) < 0)
            shmem_global_exit(2);
        close(log_pipe[1]);
        /* Retain the undrained read end until process exit: the diagnostic
         * writer must block rather than receive SIGPIPE. */
        while (nanosleep(&delay, &delay) != 0) {}
        shmem_finalize();
        printf("Application finalized despite blocked idle diagnostics\n");
        return 0;
    } else if (strcmp(argv[1], "idle-then-wait") == 0) {
        struct timespec delay = {65, 0};
        while (nanosleep(&delay, &delay) != 0) {}
        if (shmem_my_pe() == 0)
            shmem_int_wait_until(&flag, SHMEM_CMP_NE, 0);
        else
            for (;;) sleep(1);
    } else if (strcmp(argv[1], "progress") == 0) {
        for (int i = 0; i < 5; i++) {
            shmem_barrier_all();
            sleep(1);
        }
    } else if (strcmp(argv[1], "finalize") == 0) {
        if (shmem_my_pe() != 0)
            for (;;) sleep(1);
    } else if (strcmp(argv[1], "threads") == 0) {
        pthread_t worker;
        if (provided != SHMEM_THREAD_MULTIPLE)
            shmem_global_exit(2);
        if (shmem_my_pe() == 0) {
            if (pthread_create(&worker, NULL, blocked_thread, NULL) != 0)
                shmem_global_exit(2);
            for (;;) {
                (void)shmem_my_pe();
                usleep(100000);
            }
        } else {
            for (;;) sleep(1);
        }
    } else {
        shmem_global_exit(2);
    }
    shmem_finalize();
    return 0;
}
