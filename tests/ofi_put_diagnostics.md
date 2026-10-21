# OFI epoch comparison and put diagnostics

Set these variables uniformly on every PE before initialization. Forward
them through your cluster's existing launcher environment mechanism.

| Variable | Default | Values |
| --- | --- | --- |
| `SHMEM_OFI_EPOCH_SYNC` | `1` | `1`: direct blocking puts wait for transmit completion; quiet completes fenced delivery epochs. `0`: restore ordinary endpoint/counter completion; blocking direct puts quiet before source reuse. |
| `SHMEM_OFI_PUT_DIAGNOSTICS` | `0` | `1`: collect put diagnostics and print one report on PE 0 at normal finalization. `0`: no timing, statistics updates, report storage, or report collectives. |

Legacy `SMA_` aliases are accepted; `SHMEM_` takes precedence. Boolean
values are numeric. These settings are read at initialization, not changed
mid-run.

Run the same benchmark, message sizes, placement, bounce parameters, and
iteration count in all four modes:

| Epoch sync | Diagnostics | Purpose |
| --- | --- | --- |
| `0` | `0` | Counter-mode performance without measurement overhead. |
| `1` | `0` | Epoch-mode performance without measurement overhead. |
| `0` | `1` | Locate counter-mode costs. |
| `1` | `1` | Locate epoch-mode costs. |

For example, set the desired pair before your existing benchmark launcher:

```sh
export SHMEM_OFI_EPOCH_SYNC=1
export SHMEM_OFI_PUT_DIAGNOSTICS=1
export SHMEM_BOUNCE_SIZE=0
```

Epoch mode allocates a separate uncounted transmit endpoint/CQ per context.
Counter mode does not allocate those resources or request `FI_FENCE` solely
for epochs. A build using `--enable-ofi-fence` still requests fence capability
for the existing signal optimization. Counter mode restores injection-first
selection and the original endpoint/counter completion for direct puts. The epoch mode's
relaxed public fence is unchanged.

## Counter-mode reference path

With epochs and diagnostics both disabled, ordinary direct puts use the
`fi_write` fragment loop from commit
`cc47ade0a0388304c47d2e8ec4fbc5b53de83b30`. The mode is selected before the
loop; the loop has no epoch checks, diagnostic snapshots, or timing work.
Epoch posting, epoch quiet, and measured direct posting use separate
functions. Write performance-counter queries and NBI signal ordering skip
their epoch locks when epochs are disabled.

`fi_write` uses the endpoint's existing completion defaults. The shared
default endpoint is created with zero operation flags; separate context
endpoints are created with `FI_DELIVERY_COMPLETE`. The earlier counter-mode
implementation used explicit `FI_DELIVERY_COMPLETE` via `fi_writemsg` for
every ordinary direct put, which changed both the provider entry point and,
on the shared default endpoint, the requested completion behavior.

Counter-mode put-with-signal retains its original explicit
`FI_DELIVERY_COMPLETE` payload writes via `fi_writemsg`. Enabling diagnostics
preserves these choices: ordinary direct puts still use `fi_write`, and
signal payloads still use `fi_writemsg`. Runtime mode selection and other
instrumented helpers remain, so this is not an assertion of identical
generated code or benchmark performance.

## Report scope and collection

The report begins with `OFI_PUT_DIAGNOSTICS begin report_pe=0` and ends with
`OFI_PUT_DIAGNOSTICS fragments_per_terminal=... end`. It goes to **stdout**.
Only PE 0 prints it, but counts and timings include every PE and all its
transport contexts, including contexts destroyed earlier in the run.

The measurement window covers the library lifetime up to the report before
team and transport teardown, including initialization and the first normal
shutdown barrier. It does not separate warmup from measured benchmark
iterations. Statistics are frozen before the reporting fcollect/barrier,
so report traffic and final teardown are excluded.

Report collection uses the existing internal fcollect protocol on dedicated
symmetric heap buffers allocated in the uniform initialization sequence.
It works with shared-library builds and does not assume that a hierarchical
barrier alone progresses remote reads. Storage per PE is
`(number_of_PEs + 1) * sizeof(diagnostic_snapshot)` plus
`SHMEM_COLLECT_SYNC_SIZE * sizeof(long)`; each instrumented context also has
one local snapshot and mutex. The gather is outside the benchmark loop but
adds to finalization time when diagnostics are enabled.

An abnormal exit or failure before normal finalization does not produce this
report. All PEs must use matching settings and enter normal finalization.

Each count row contains `total` across PEs and `max_rank`, the largest
per-PE total. Each timing row contains:

- `calls`: number of timed intervals across PEs.
- `sum_s`: sum of interval durations across PEs.
- `mean_us`: mean interval duration.
- `max_call_us`: longest individual interval.
- `max_rank_s` and `max_rank_pe`: largest cumulative time on a PE, and its rank.

Times are **inclusive and overlapping**. Do not add all rows together or
interpret summed rank times as elapsed job time. Instrumentation itself
adds clock, counter, and statistics-lock overhead; compare throughput using
the two diagnostics-off runs.

## Finding the bottleneck

| Observation | Interpretation |
| --- | --- |
| Large `transmit_wait` time / many `transmit_empty_cq_polls` | Blocking source release spends time polling transmit completions. Fragmented blocking puts serialize this wait per fragment. |
| Large `terminal_wait` / many terminal empty polls | Fenced delivery synchronization is expensive. Compare with counter-mode `counter_wait`. |
| `fragments_per_terminal` near 1 | Little grouping benefit; signals or internal collective notification boundaries may synchronize frequently. |
| Many `empty_epoch_sync_calls` | Quiet and notification paths often visit an empty epoch. Compare `epoch_sync` mean time and call count. |
| Large `payload_post` time / many `payload_eagain_retries` | Posting encounters provider/resource pressure or spends time driving retry progress. Posting time includes retries. |
| Large `put_lock_wait` or `epoch_lock_wait` | Host threads contend for posting or synchronization locks. The latter includes waiting for a blocking direct put to release the epoch lock. |
| Large `counter_wait` | Ordinary write/atomic counter completion dominates; in counter mode this also releases direct-put sources. |
| Large `bounce_allocate_copy` or `bounce_drain` | Bounce copying, pool pressure, or bounce-buffer completion consumes time. Allocation/copy timing includes bounce-buffered atomic users too. |
| Large `read_wait` | Read/fetch completion contributes to quiet time; this includes calls with no pending reads. |
| Large `context_create` | Context/resource setup contributes substantial startup cost. Compare epoch and counter modes. |
| `max_rank_s` much larger than average cumulative rank time | Rank imbalance, placement, or contention is relevant; inspect the reported rank. |
| Zero benchmark-related direct bytes/fragments | The benchmark may use shared-memory, injection, or bounce paths instead of the direct OFI path. Verify placement and effective size limits. |

`direct_put` includes mapping, locks, posting, and transmit waits in epoch
mode. In counter mode it measures posting; later source completion appears
in `put_quiet` / `counter_wait`. `put_quiet` includes epoch synchronization,
bounce draining, and ordinary write-counter waiting, but read waiting is
reported separately. `injected_put` measures the whole injection helper.
Control atomics retain their existing accounting and are not counted as
direct payload fragments. Counts refer to transport calls/fragments rather
than necessarily one public API call, especially for strided operations.

## Cluster validation

Run `ofi_epoch.c` in both feature modes, with diagnostics on and off. Its
source-reuse, quiet, signal, broadcast, and reduction checks apply to both
modes; pending-until-quiet performance-counter assertions apply only to
epoch mode. For these runs the payload must exceed the provider injection
limit and the chosen bounce threshold on the bounce-enabled context.

With diagnostics on, check that each run contains one begin/end report.
With diagnostics off, there must be no `OFI_PUT_DIAGNOSTICS` report.
In counter mode, `epoch_fragments`, `transmit_completions`, and
`terminal_writes` must be zero. For an OFI direct-write workload in epoch
mode, those counters should show the corresponding operations. Diagnostic
report fcollect traffic must not appear in payload counters.

For additional shutdown coverage, use a shared-library build and repeat
with one PE, several nodes, manual progress, hierarchical barriers,
different fcollect algorithms, context creation/destruction, and
`SHMEM_THREAD_MULTIPLE`. The agent has performed static analysis only;
no runtime or performance result is claimed.
