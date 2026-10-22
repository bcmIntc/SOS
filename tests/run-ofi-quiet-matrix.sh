#!/bin/sh
# Usage: sh run-ofi-quiet-matrix.sh /abs/ofi_quiet_oracle BYTES|all launcher args...
# Cluster source: /home/mfbrown/Code/SOS; build: /home/mfbrown/Code/SOS/build.
# Binaries are in build/tests/. Example from the source directory:
# SOS_OFI_LOG_DIR=./logs/quiet-suite-new sh tests/run-ofi-quiet-matrix.sh \
#   /home/mfbrown/Code/SOS/build/tests/ofi_quiet_oracle all mpirun -n 2 -ppn 1 -no-vni
# "all" validates the counter-wait model and local model negative control,
# then tests 1024/4096/8192.
# SOS_OFI_QUIET_MODEL may override the sibling ofi_quiet_model binary.
# SOS_OFI_COUNTER_WAIT_MODEL may override the sibling ofi_counter_wait_model.
# Single-size runs require separately validated counter-wait and negative-control models.
# Requires two hosts with a TCP control route. No FI_MORE, arena or
# payload-coalescing qualification. Delivery/accounting review remains separate.
set -eu
if [ "$#" -lt 3 ]; then
    echo "usage: $0 /abs/ofi_quiet_oracle BYTES|all launcher args..." >&2
    exit 2
fi
binary=$1
bytes=$2
shift 2
case "$binary" in /*) ;; *) echo "test binary must be absolute" >&2; exit 2 ;; esac
log_dir=${SOS_OFI_LOG_DIR:-./ofi-quiet-logs}
if [ "$bytes" = all ]; then
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
    model_binary=${SOS_OFI_QUIET_MODEL:-${binary%/*}/ofi_quiet_model}
    counter_wait_binary=${SOS_OFI_COUNTER_WAIT_MODEL:-${binary%/*}/ofi_counter_wait_model}
    case "$model_binary" in
        /*) ;;
        *) echo "SOS_OFI_QUIET_MODEL must be absolute" >&2; exit 2 ;;
    esac
    case "$counter_wait_binary" in
        /*) ;;
        *) echo "SOS_OFI_COUNTER_WAIT_MODEL must be absolute" >&2; exit 2 ;;
    esac
    if [ ! -f "$binary" ] || [ ! -x "$binary" ] ||
       [ ! -f "$model_binary" ] || [ ! -x "$model_binary" ] ||
       [ ! -f "$counter_wait_binary" ] || [ ! -x "$counter_wait_binary" ]; then
        echo "all requires existing executable oracle and model binaries; no builds are performed" >&2
        exit 2
    fi
    # Reject stale evidence before running the control or any cluster case.
    for evidence in negative-control.log negative-control.exit-status \
                    negative-control-binary.sha256 negative-control-test.sha256 \
                    counter-wait-model.log counter-wait-model.exit-status \
                    counter-wait-model-binary.sha256 \
                    matrix-1024 matrix-4096 matrix-8192; do
        if [ -e "$log_dir/$evidence" ]; then
            echo "use a new log directory; $log_dir/$evidence already exists" >&2
            exit 2
        fi
    done
    mkdir -p "$log_dir"
    sha256sum "$counter_wait_binary" >"$log_dir/counter-wait-model-binary.sha256"
    status=0
    timeout "${SOS_OFI_TEST_TIMEOUT:-120s}" "$counter_wait_binary" \
        >"$log_dir/counter-wait-model.log" 2>&1 || status=$?
    printf '%s\n' "$status" >"$log_dir/counter-wait-model.exit-status"
    if [ "$status" != 0 ] ||
       ! grep -Fxq "OFI counter wait and rebase model checks completed" "$log_dir/counter-wait-model.log"; then
        echo "FAIL/INVALID: $log_dir/counter-wait-model.log (exit $status); no cluster cases run" >&2
        exit 1
    fi
    echo "Counter wait and rebase model checks completed: $log_dir/counter-wait-model.log"
    sha256sum "$model_binary" >"$log_dir/negative-control-binary.sha256"
    sha256sum "$script_dir/test_ofi_quiet_oracle.py" >"$log_dir/negative-control-test.sha256"
    status=0
    # This driver runs both normal-delivery and early-return cases locally;
    # the early-return processes must fail with a detected payload mismatch.
    python3 "$script_dir/test_ofi_quiet_oracle.py" "$model_binary" -v \
        >"$log_dir/negative-control.log" 2>&1 || status=$?
    printf '%s\n' "$status" >"$log_dir/negative-control.exit-status"
    if [ "$status" != 0 ]; then
        echo "FAIL/INVALID: $log_dir/negative-control.log (exit $status); no cluster cases run" >&2
        exit 1
    fi
    echo "Delayed-delivery model checks completed: $log_dir/negative-control.log"
    for matrix_bytes in 1024 4096 8192; do
        SOS_OFI_LOG_DIR="$log_dir/matrix-$matrix_bytes" \
            sh "$script_dir/run-ofi-quiet-matrix.sh" "$binary" "$matrix_bytes" "$@"
    done
    echo "Quiet observation suite completed; delivery/accounting review remains required."
    exit 0
fi
case "$bytes" in ''|*[!0-9]*) echo "BYTES must be an integer in 1-8192" >&2; exit 2 ;; esac
if [ "$bytes" -lt 1 ] || [ "$bytes" -gt 8192 ]; then
    echo "choose BYTES above negotiated injection and at/below 8192" >&2
    exit 2
fi
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
