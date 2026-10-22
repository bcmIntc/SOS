#!/bin/bash
# Build the current checkout and its immediate/quiet regression binaries and models.
# Run on the cluster with its compiler, MPI and libfabric modules loaded.
# Cluster source directory: /home/mfbrown/Code/SOS.
# Default SOS build directory: /home/mfbrown/Code/SOS/build.
# Example: bash /home/mfbrown/Code/SOS/scripts/build-ofi-immediate.sh
# Pass [build-directory] to override the default, from any working directory.
# Existing VPATH configurations retain their compiler and configure options.
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

# Resolve an optional relative build path from the caller's working directory.
mkdir -p -- "${1:-/home/mfbrown/Code/SOS/build}"
sos_build_dir=$(cd -- "${1:-/home/mfbrown/Code/SOS/build}" && pwd -P)
if [ "$sos_build_dir" = "$sos_source_dir" ]; then
    echo "use a separate build directory" >&2
    exit 2
fi

sos_existing_build=false
if [ -f "$sos_build_dir/Makefile" ] && [ -f "$sos_build_dir/config.status" ]; then
    sos_configured_source=$(sed -n 's/^abs_top_srcdir = //p' "$sos_build_dir/Makefile")
    if [ -z "$sos_configured_source" ]; then
        echo "cannot determine the configured source directory from $sos_build_dir/Makefile" >&2
        exit 2
    fi
    # Automake may retain /build/.. in the absolute path. Resolve it before
    # comparing, without evaluating Makefile content as shell code.
    sos_configured_source=$(cd -- "$sos_configured_source" && pwd -P)
    if [ "$sos_configured_source" != "$sos_source_dir" ]; then
        printf 'build directory uses source %s, but this helper belongs to %s\n' \
            "$sos_configured_source" "$sos_source_dir" >&2
        echo "run the helper from that source checkout or choose another build directory" >&2
        exit 2
    fi
    sos_existing_build=true
fi

# Capture source identity before autogen modifies generated files.
{
    printf 'git_commit=%s\nbranch=%s\nsource_directory=%s\nbuild_directory=%s\n' \
        "$sos_commit_id" "$sos_branch" "$sos_source_dir" "$sos_build_dir"
    printf 'build_started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'pre_build_status_begin\n%s\npre_build_status_end\n' "$sos_source_status"
} > "$sos_build_dir/sos-build-source.txt"

cd "$sos_source_dir"
bash "$sos_source_dir/autogen.sh"
cd "$sos_build_dir"
if [ "$sos_existing_build" = true ]; then
    echo "Refreshing the existing VPATH configuration with its original options."
    bash ./config.status --recheck
    bash ./config.status
else
    CC=${CC:-mpicc} CXX=${CXX:-mpicxx} "$sos_source_dir/configure" \
        --srcdir="$sos_source_dir" \
        --with-ofi="${SOS_OFI_PREFIX:-/opt/cray/libfabric/1.22.0}" \
        --with-xpmem="${SOS_XPMEM_PREFIX:-/usr/lib}" \
        --enable-pmi-mpi --disable-fortran \
        --enable-ofi-mr=basic --enable-mr-endpoint \
        --enable-ofi-manual-progress --enable-manual-progress \
        --enable-threads --disable-ofi-hmem \
        --disable-libtool-wrapper --enable-hierarchical-barrier
fi
make -j "${SOS_BUILD_JOBS:-8}" ofi-regressions

printf 'build_completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >> "$sos_build_dir/sos-build-source.txt"
printf 'Built SOS Git commit %s\nSource record: %s/sos-build-source.txt\n' \
    "$sos_commit_id" "$sos_build_dir"
