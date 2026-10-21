# OFI bounce-buffer batching regression

`ofi_bounce_batch.c` checks source reuse, a small bounce pool with contiguous
and disjoint updates, fence followed by notification, queued work on a created
context while waiting or testing on the default context, transition to a
nonblocking put, and context destruction.

It has not been built or run. Its syntax has been checked without producing
objects or executables. Current workspace instructions permit only static
analysis.

For future runtime verification on an OFI installation, place the two PEs on
different nodes so the shared-memory transport cannot bypass these paths.
The 1024-byte blocks must exceed the selected provider's injection size; adjust
`BLOCK_BYTES` if necessary.

Use an existing test build/launch procedure to run with:

- `SHMEM_BOUNCE_SIZE=4096`
- `SHMEM_MAX_BOUNCE_BUFFERS=2`
- `SHMEM_OFI_BOUNCE_BATCH_COUNT=8`
- `SHMEM_OFI_BOUNCE_BATCH_BYTES=0`
- `SHMEM_OFI_BOUNCE_BATCH_USEC=100`

Repeat with batch count 1 (default behavior), count 2 (threshold flushing),
count 32 (pool-pressure flushing), byte threshold 1024, and age limit 0.
Repeat with a larger pool and a bounce size equal to one block so writes
remain separate. Run the same regression with argument `--multiple` to check
the immediate-posting fallback; this initializes with SHMEM_THREAD_MULTIPLE
but does not stress concurrent application calls.

These public-API checks establish payload and progress behavior when run.
They do not prove that a specific batching branch executed or measure any
performance gain; provider tracing or separate instrumentation is needed for
that assessment. In particular, the notification put independently flushes
the queue in the fence scenario, and quiet independently flushes it after
the nonblocking put. Those scenarios check combined payload correctness,
not each flush boundary in isolation. The matrix does not identify which
count, byte, or age threshold caused submission. Shared-memory transitions
need a separate placement scenario that exercises both communication planes.
