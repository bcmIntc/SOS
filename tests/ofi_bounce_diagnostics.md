# Comparing OFI bounce batching

The benchmark runs on your other machine. No project runtime tests or
benchmarks have been executed in this workspace.

## Switches

- `SHMEM_OFI_BOUNCE_BATCH_DISABLE=1` forces immediate posting regardless of
  batch count. It also bypasses batching flush/progress work before added
  context locks and restores the allocator's direct CQ polling under pool
  pressure. The bounce pool remains enabled.
- `SHMEM_OFI_BOUNCE_BATCH_DISABLE=0` retains the existing behavior:
  count above 1 enables eligible contexts; count 1 posts immediately.
- `SHMEM_OFI_BOUNCE_BATCH_DIAGNOSTICS=1` collects counters and timings with
  either switch setting. Default 0 performs no diagnostic clock reads or
  atomic metric updates, and prints no diagnostic records.

The explicit disable switch overrides count/byte/age settings. It does not
select a different transport or disable ordinary bounce buffering. This is a
comparison within the instrumented binary, not an exact recreation of the
original pre-feature binary: compiled checks and the expanded buffer layout
remain. MULTIPLE and provider restrictions still determine eligibility.

## Four matching runs

Keep the binary, provider, message size, batch count, window size, warmup,
iteration count, PE count, placement, and other environment variables the same.
Prefer one message size per invocation when the benchmark supports that.
Reports cover the context's entire lifetime, including warmup, all message
sizes, and teardown.

Replace the array below with your actual launch command and arguments. These
commands are for the benchmark machine, and have not been executed here.

```bash
benchmark_cmd=(oshrun -n 2 ./your-benchmark)

# Performance comparison with instrumentation off.
env SHMEM_OFI_BOUNCE_BATCH_COUNT=8 \
    SHMEM_OFI_BOUNCE_BATCH_DISABLE=1 \
    SHMEM_OFI_BOUNCE_BATCH_DIAGNOSTICS=0 \
    "${benchmark_cmd[@]}" >off.out 2>off.err

env SHMEM_OFI_BOUNCE_BATCH_COUNT=8 \
    SHMEM_OFI_BOUNCE_BATCH_DISABLE=0 \
    SHMEM_OFI_BOUNCE_BATCH_DIAGNOSTICS=0 \
    "${benchmark_cmd[@]}" >on.out 2>on.err

# Matching diagnostic runs: use these to locate costs.
env SHMEM_OFI_BOUNCE_BATCH_COUNT=8 \
    SHMEM_OFI_BOUNCE_BATCH_DISABLE=1 \
    SHMEM_OFI_BOUNCE_BATCH_DIAGNOSTICS=1 \
    "${benchmark_cmd[@]}" >off-diag.out 2>off-diag.err

env SHMEM_OFI_BOUNCE_BATCH_COUNT=8 \
    SHMEM_OFI_BOUNCE_BATCH_DISABLE=0 \
    SHMEM_OFI_BOUNCE_BATCH_DIAGNOSTICS=1 \
    "${benchmark_cmd[@]}" >on-diag.out 2>on-diag.err
```

Use the same batch count as the slow run if it differs from 8. Repeat/reorder
the performance runs to assess machine variability. Diagnostic clocks and
atomics perturb short operations; use the first two runs for performance
numbers and the latter two for explanation.

## Reading the records

`SOS_OFI_BATCH_CONFIG` on PE 0 prints the requested/effective count, disable
state, thresholds, bounce size, pool size, injection limit, thread level, and
provider. Check that the launcher propagated the requested environment.

`SOS_OFI_BATCH` prints one key/value record per PE/context when it is destroyed,
or during finalization for the default context. Context identity includes
`pe`, `ctx`, and team start/stride/size. Distinct teams with identical membership
can share these identifiers; they are descriptive, not a globally unique ID.
Failed/aborted runs may not reach teardown and produce no summary.

All `_ns` fields are accumulated elapsed nanoseconds. They are not CPU time
or per-operation averages. Timers are **inclusive and overlapping**: do not
add them to estimate total wall time. Atomic counter updates are safe with
MULTIPLE even when context locks are absent.

| Observation | What to investigate |
| --- | --- |
| `batching=0`, `bounce=0`, or `queued_calls=0` | Work did not qualify: check provider restrictions, thread level, injection limit, direct/NBI paths, and bounce configuration. |
| High `nbi_calls` or `inject_calls`, no queueing | The benchmark exercises a direct path. Batching cannot coalesce these operations. |
| High `flush_checks`, few `flushes`, low `coalesced_calls` | Many empty FIFO checks with little submission reduction. Disabled mode bypasses that work. |
| Small `flush_segments / flushes` | Batches end early. Inspect the reason counts, especially direct, shared, progress, quiet, and age. |
| High `age_checks`, frequent `flush_age` | Age checking or the configured age limit may be counterproductive. Compare a separate run with `SHMEM_OFI_BOUNCE_BATCH_USEC=0`. |
| High `copy_ns` or `alloc_ns` | Copying or pool allocation costs may outweigh saved submissions. |
| High `pool_pressure` and `pool_ns` | The pool saturates. `pool_ns` includes pressure-triggered flushing and CQ polling. |
| High `submit_ns`, `eagain`, or `retry_ns` | Provider submission/resource pressure. `submit_ns` times each ordinary data-put FI call; `retry_ns` times EAGAIN handling, including CQ/progress work, for all transport operations using the retry helper. |
| High `quiet_cq_ns` | Time in bounce-buffer reclamation at write quiet, including the pool-lock interval. |
| High `quiet_cntr_ns` | Time in write-counter completion waits, including waits whose threshold is already satisfied. |
| Larger `oldest_max_ns` | Queued work stays unsubmitted longer before a flush starts. |
| `put_nb_ns`, `nbi_ns`, `scalar_ns`, or `large_ns` rises | Inclusive transport-path time increased, including lookup/locks and nested posting or queue work. `put_nb_ns` excludes the separate source-completion wait; write waits are represented in `quiet_ns`. |

Other counters:

- `coalesced_calls / queued_calls`: fraction of queued source segments appended
  to an existing buffer. Handle zero denominators.
- `bounce_posts`, `bounce_post_bytes`: successful ordinary bounce-put writes,
  both immediate and queued. `large_posts` counts successful large-put
  fragments. FI retry attempts are timed but not counted as successful posts.
- `allocations`: bounce-buffer allocations, including atomic buffers.
  `cq_events` includes all reclaimed buffers from that pool, including atomics.
- `queue_segments_max`: maximum source-segment count retained before a flush.
  `oldest_sum_ns / flushes` is the mean oldest-buffer age at flush start, not
  mean residence time of every buffer.
- `flush_count`, `flush_bytes`, `flush_age`, `flush_pool`, `flush_quiet`,
  `flush_fence`, `flush_direct`, `flush_shared`, `flush_progress`,
  `flush_destroy`, `flush_overflow` count nonempty flushes by reason.
  The byte payload total is named `flushed_bytes`; `flush_bytes` is the
  byte-threshold reason count. Count wins if count and byte thresholds both
  fire on the same enqueue.
- Transport helper call counts are not necessarily public API call counts;
  strided operations and collectives can use the helpers repeatedly.
- These diagnostics do not time the shared-memory transfer itself, reads,
  atomics, collective synchronization, or the whole application.

## Manual regression expectations

Run the existing `ofi_bounce_batch.c` regression with both disable settings
and diagnostics enabled, using messages above injection size and a working
bounce pool. Also repeat its `--multiple` mode.

For a normally finalized context with diagnostics active:

- Disabled mode must report `batching=0`, `queued_calls=0`,
  `coalesced_calls=0`, `flush_checks=0`, and `flushes=0`; ordinary put,
  submission, and completion metrics can still be nonzero.
- Queued source segments should all be submitted by teardown:
  `flush_segments == queued_calls` and `flushed_bytes == queued_bytes`.
- The sum of reason counts should equal `flushes`.
- Ordinary bounce puts satisfy
  `bounce_posts == queued_calls - coalesced_calls + immediate_bounce_calls`.

These runtime expectations have not been verified here. They complement
payload checks and static inspection rather than prove a performance fix.
