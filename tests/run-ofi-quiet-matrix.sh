#!/bin/sh
# Usage: sh run-ofi-quiet-matrix.sh /abs/ofi_quiet_oracle BYTES launcher args...
# Requires a separately validated local model negative control and two hosts
# with a TCP control route. No FI_MORE, arena or payload-coalescing qualification.
set -eu
if [ "$#" -lt 3 ]; then
    echo "usage: $0 /abs/ofi_quiet_oracle BYTES launcher args..." >&2
    exit 2
fi
binary=$1
bytes=$2
shift 2
case "$binary" in /*) ;; *) echo "test binary must be absolute" >&2; exit 2 ;; esac
case "$bytes" in ''|*[!0-9]*) echo "BYTES must be an integer in 1-8192" >&2; exit 2 ;; esac
if [ "$bytes" -lt 1 ] || [ "$bytes" -gt 8192 ]; then
    echo "choose BYTES above negotiated injection and at/below 8192" >&2
    exit 2
fi
log_dir=${SOS_OFI_LOG_DIR:-./ofi-quiet-logs}
mkdir -p "$log_dir"
if [ -e "$log_dir/matrix-summary.tsv" ]; then
    echo "use a new log directory; matrix-summary.tsv already exists" >&2
    exit 2
fi
printf 'pool\tcq\tcounter\tmode\tbytes\texit_status\tlog\n' >"$log_dir/matrix-summary.tsv"
printf '%s\n' "$@" >"$log_dir/launcher-arguments.txt"
sha256sum "$binary" >"$log_dir/test-binary.sha256"
export SHMEM_INFO=1 SHMEM_DEBUG=0 SHMEM_BOUNCE_SIZE=8192
export SHMEM_OFI_PROVIDER=cxi SHMEM_OFI_STX_MAX=0 SHMEM_OFI_STX_AUTO=0
export SHMEM_BOUNCE_SHEAP=1 SHMEM_OFI_BOUNCE_LOCAL_MR=1 SHMEM_OFI_PUT_BATCH_STATS=1
unset SHMEM_OFI_PUT_PIGGYBACK SMA_OFI_PUT_PIGGYBACK
unset SHMEM_OFI_BOUNCE_ARENA SMA_OFI_BOUNCE_ARENA
for pool in 1 2 128; do
    export SHMEM_MAX_BOUNCE_BUFFERS=$pool
    for cq in 1 8; do
        export SHMEM_OFI_CQ_BATCH_SIZE=$cq
        for arm in 0 1; do
            export SHMEM_OFI_BOUNCE_COUNTER_RETIRE=$arm
            for mode in blocking nbi; do
                log=$log_dir/pool-$pool-cq-$cq-counter-$arm-$mode.log
                status=0
                timeout "${SOS_OFI_TEST_TIMEOUT:-120s}" "$@" "$binary" "$bytes" "$mode" \
                    >"$log" 2>&1 || status=$?
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$pool" "$cq" "$arm" "$mode" "$bytes" "$status" "$log" \
                    >>"$log_dir/matrix-summary.tsv"
                if [ "$status" != 0 ]; then
                    echo "FAIL/INVALID: $log (exit $status); G3 remains open" >&2
                    exit 1
                fi
                if ! grep -Fq "OFI quiet oracle completed: mode=$mode bytes=$bytes epochs=4 writes=17 control=tcp receiver_shmem_calls=0" "$log"; then
                    echo "FAIL/INVALID: $log lacks oracle completion evidence" >&2
                    exit 1
                fi
                if ! awk -v arm="$arm" -v cq="$cq" -v mode="$mode" '
                    /OFI immediate bounce:/ {
                        delete v
                        for (i=1; i<=NF; i++) {
                            n=split($i,a,"=")
                            if (n==2) v[a[1]]=a[2]
                        }
                        seen++
                        count=split("local_mr retirement cq_batch bounce_puts counter_puts cq_puts reclaimed groups stx_max stx_idx", required, " ")
                        for (j=1; j<=count; j++)
                            if (!(required[j] in v)) bad=1
                        if (v["local_mr"] != 1 || v["cq_batch"] != cq ||
                            !("stx_max" in v) || v["stx_max"] != 0 ||
                            !("stx_idx" in v) || v["stx_idx"] != -1 ||
                            v["retirement"] != (arm ? "counter" : "cq")) bad=1
                        if (mode=="blocking") {
                            if (v["bounce_puts"] != 68 ||
                                v["counter_puts"] != (arm ? 68 : 0) ||
                                v["cq_puts"] != (arm ? 0 : 68) ||
                                v["reclaimed"] != (arm ? 68 : 0) ||
                                (arm && v["groups"]+0 <= 0)) bad=1
                        } else if (v["bounce_puts"] != 0 ||
                                   v["counter_puts"] != 0 ||
                                   v["cq_puts"] != 0 || v["reclaimed"] != 0) bad=1
                    }
                    END { exit !(seen==1 && !bad) }
                ' "$log"; then
                    echo "FAIL/INVALID: $log lacks valid path/ownership evidence" >&2
                    exit 1
                fi
                echo "quiet observation case completed: $log"
            done
        done
    done
done
echo "Quiet observation matrix completed; combine with negative-control and delivery/accounting evidence."
