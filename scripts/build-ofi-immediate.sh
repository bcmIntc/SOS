#!/bin/bash
# Build the current checkout and its immediate/quiet regression binaries and models.
# Run on the cluster with its compiler, MPI and libfabric modules loaded.
# Cluster source directory: /home/mfbrown/Code/SOS.
# Default SOS build directory: /home/mfbrown/Code/SOS/build.
# Example: bash /home/mfbrown/Code/SOS/scripts/build-ofi-immediate.sh
# Pass [build-directory] to override the default.
set -euo pipefail

if [ "$#" -gt 1 ]; then
    echo "usage: bash $0 [build-directory]" >&2
    exit 2
fi

sos_source_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
sos_commit_id=$(git -C "$sos_source_dir" rev-parse --verify HEAD)
sos_branch=$(git -C "$sos_source_dir" symbolic-ref --quiet --short HEAD || printf 'detached')
sos_source_status=$(git -C "$sos_source_dir" status --porcelain --untracked-files=normal)

printf 'SOS source: %s\nSOS Git commit: %s\nSOS branch: %s\n' \
    "$sos_source_dir" "$sos_commit_id" "$sos_branch"
if [ -n "$sos_source_status" ]; then
    echo "SOS working tree has changes; see sos-build-source.txt for the pre-build status."
fi

cd "$sos_source_dir"
mkdir -p -- "${1:-/home/mfbrown/Code/SOS/build}"
sos_build_dir=$(cd -- "${1:-/home/mfbrown/Code/SOS/build}" && pwd -P)
if [ "$sos_build_dir" = "$sos_source_dir" ]; then
    echo "use a separate build directory" >&2
    exit 2
fi

# Capture source identity before autogen modifies generated files.
{
    printf 'git_commit=%s\nbranch=%s\nsource_directory=%s\nbuild_directory=%s\n' \
        "$sos_commit_id" "$sos_branch" "$sos_source_dir" "$sos_build_dir"
    printf 'build_started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'pre_build_status_begin\n%s\npre_build_status_end\n' "$sos_source_status"
} > "$sos_build_dir/sos-build-source.txt"

bash "$sos_source_dir/autogen.sh"
cd "$sos_build_dir"
CC=${CC:-mpicc} CXX=${CXX:-mpicxx} "$sos_source_dir/configure" \
    --with-ofi="${SOS_OFI_PREFIX:-/opt/cray/libfabric/1.22.0}" \
    --with-xpmem="${SOS_XPMEM_PREFIX:-/usr/lib}" \
    --enable-pmi-mpi --disable-fortran \
    --enable-ofi-mr=basic --enable-mr-endpoint \
    --enable-ofi-manual-progress --enable-manual-progress \
    --enable-threads --disable-ofi-hmem \
    --disable-libtool-wrapper --enable-hierarchical-barrier
make -j "${SOS_BUILD_JOBS:-8}"
make -C tests ofi_immediate ofi_counter_init ofi_quiet_oracle \
    ofi_quiet_model ofi_counter_wait_model

printf 'build_completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "$sos_build_dir/sos-build-source.txt"
printf 'Built SOS Git commit %s\nSource record: %s/sos-build-source.txt\n' \
    "$sos_commit_id" "$sos_build_dir"
