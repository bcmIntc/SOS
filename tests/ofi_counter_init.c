/* The matrix launcher expects initialization to reject invalid counter modes.
 * If a restriction is accidentally removed, this program returns success and
 * the launcher reports a failed negative test.
 */
#include <shmem.h>
#include <string.h>

int
main(int argc, char **argv)
{
    int level = SHMEM_THREAD_SINGLE, provided;
    if (argc == 2 && !strcmp(argv[1], "multiple"))
        level = SHMEM_THREAD_MULTIPLE;
    else if (argc != 1)
        return 1;
    shmem_init_thread(level, &provided);
    shmem_finalize();
    if (provided != level)
        return 77; /* Non-threaded builds may legally provide SINGLE. */
    return 0;
}
