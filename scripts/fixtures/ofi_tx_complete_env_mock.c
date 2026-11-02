/* -*- C -*- */
#include "../../src/shmem_env.c"

int shmem_internal_my_pe;

void shmem_runtime_abort(int status, const char message[])
{
    (void) message;
    exit(status);
}

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 5) return 2;
    if (shmem_internal_parse_env()) return 2;
    if (shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS != (bool) atoi(argv[1]) ||
        shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_provided != (bool) atoi(argv[2])) {
        fprintf(stderr, "Unexpected parsed enable/provided values\n");
        return 2;
    }
    if (argc == 5 &&
        (shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_LOWER_CUTOFF != strtoull(argv[3], NULL, 10) ||
         shmem_internal_params.OFI_CXI_TX_COMPLETE_PUTS_UPPER_CUTOFF != strtoull(argv[4], NULL, 10))) {
        fprintf(stderr, "Unexpected parsed size cutoffs\n");
        return 2;
    }
    return 0;
}
