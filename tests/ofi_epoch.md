# OFI large-write epoch regression

Use `SHMEM_OFI_EPOCH_SYNC=1` (default) for the epoch behavior described below.
With `SHMEM_OFI_EPOCH_SYNC=0`, direct writes use delivery counters and blocking
puts quiet before returning; pending-until-quiet assertions are skipped.
Payload, source-reuse, quiet, signal, and collective checks still apply.
Run both modes with `SHMEM_OFI_PUT_DIAGNOSTICS=0` and `1`; see
[`ofi_put_diagnostics.md`](ofi_put_diagnostics.md) for the comparison matrix
and final PE 0 report.

`ofi_epoch.c` covers multiple large NBI writes to multiple destinations,
repeated and empty quiet, created contexts, blocking-put source reuse,
fence leaving epoch completion pending, quiet followed by a small
notification, ordinary-write/quiet/large-write ordering to the same
address, blocking and NBI put-with-signal visibility, and broadcast/reduction
payloads.

The implementation creates one additional endpoint and CQ per context,
with no bound write counter. It requires provider `FI_FENCE` support.
Direct blocking puts use `FI_TRANSMIT_COMPLETE | FI_COMPLETION` and consume
one local completion per fragment before returning, releasing their source.
This local completion does not synchronize the remote epoch. Direct NBI
puts request no successful CQ entries. Both use the epoch endpoint even
below the bounce limit when the operation has no bounce-buffer/inject path.
Quiet posts a zero-byte
write with `FI_FENCE | FI_DELIVERY_COMPLETE | FI_COMPLETION` to each dirty
destination and waits for that terminal entry. Injected and bounce-buffered
puts, typed scalar `_p` operations with injection enabled, and atomics retain
their existing counter. Performance counters include bulk fragments
as issued immediately and completed once the epoch is synchronized.
Cross-endpoint ordering through fence is intentionally disabled.
Fence leaves epoch writes pending and retains the ordinary endpoint's
conditional completion fallback when total data ordering is disabled.
Use quiet for ordering across endpoints; put-with-signal still completes
epoch data before sending its signal. This relaxed fence behavior does
not provide the OpenSHMEM fence guarantee across the two endpoints.
Collective notification sites and blocking signal bindings use an internal
delivery fence so their signals cannot precede epoch payload delivery.

The fence-completion check reads local performance counters on the created
context before fence, after fence, and after quiet. It requires epoch
routing and expects completed writes to stay unchanged at fence and catch
up to issued writes at quiet.

The context without a bounce pool mixes NBI and repeated blocking puts.
Each blocking source is overwritten immediately after the call. Completed
write statistics must remain unchanged until explicit quiet; final payloads
must match the pre-overwrite data after quiet. This checks that source reuse
does not require delivery synchronization.

Use at least three PEs on separate nodes to exercise OFI rather than a
shared-memory transport. Set `SHMEM_BOUNCE_SIZE=4096`; the 128 KiB payload
exceeds the bounce limit. Bulk puts above that limit use epochs even when
they would fit within the provider's injection limit.
Repeat with bounce buffering disabled, single-endpoint mode disabled,
and total-data-ordering enabled. Also use `SHMEM_BOUNCE_SIZE=262144` so
the 128 KiB direct-context blocking puts fit below the bounce threshold;
the payload must still exceed the provider's injection limit.
Fragmentation requires a provider message
limit below the payload size (or increasing `BYTES` above that limit).

The regression has not been built or run: workspace instructions permit
static analysis only. It does not prove the absence of fabric counter
updates; provider tracing is required to verify that bulk writes use an
endpoint with no bound write counter, blocking puts generate transmit
events, and quiet generates terminal delivery events. Concurrent
SHMEM_THREAD_MULTIPLE calls and external
device memory require separate runtime validation.
