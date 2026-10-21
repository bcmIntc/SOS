# OFI direct-put transmit completion regression

`ofi_transmit_complete.c` checks source overwrite immediately after blocking
puts, delivery statistics remaining pending until quiet, multiple destinations,
repeated and empty quiet, fence before a small notification, mixed blocking and
NBI puts, nonzero and zero-byte put-with-signal, and the default context.
Receiver notification checks occur before barriers; phase barriers prevent the
next test from overwriting a payload while the receiver validates it.

Use at least two PEs on separate nodes so that the writes exercise OFI.
Choose a provider supporting `FI_FENCE` and delivery completion. Set
`SHMEM_BOUNCE_SIZE=4096`, and ensure the provider injection limit is below the
128 KiB test payload. The created private context has no bounce pool.
Repeat with `SHMEM_BOUNCE_SIZE=262144` to cover direct puts below the bounce
threshold when the context has no bounce pool.

Also exercise single-endpoint mode enabled and disabled, automatic and manual
progress, total-data-ordering configurations, and provider message limits
below the payload size to force fragmentation. The direct endpoint always
has a separate transmit context, including when ordinary endpoints use STXs.

Providers without fenced completion retain delivery-counter source waits.
For those providers, pass `--delivery-fallback` to skip the pending-before-quiet
statistics assertion while retaining all payload and ordering checks.
Exercise provider selection using `SHMEM_OFI_PROVIDER`, `SHMEM_OFI_FABRIC`,
and `SHMEM_OFI_DOMAIN`, including a provider without `FI_FENCE`.

## Completion switch and comparison matrix

`SHMEM_OFI_TRANSMIT_COMPLETE=1` (default) enables the optimization when the
provider supports it. `SHMEM_OFI_TRANSMIT_COMPLETE=0` restores the original
delivery-counter path, including its completion-token/source wait, skips
the optional capability probe, and allocates no extra endpoint or CQ.
The regression detects `0` automatically and skips only the
pending-before-quiet assertion. The manual `--delivery-fallback` argument
remains available for unsupported providers.

Run the same workload with each combination:

| Transmit complete | Diagnostics | Purpose |
| --- | --- | --- |
| `0` | `0` | Original-path performance baseline |
| `1` | `0` | Optimized-path performance |
| `0` | `1` | Original-path completion counts and timings |
| `1` | `1` | Transmit events and deferred-delivery counts and timings |

Both variables accept the `SMA_` prefix. `SHMEM_` wins when both prefixes
are set. For example, export the following before launching all PEs:

```sh
export SHMEM_OFI_TRANSMIT_COMPLETE=1
export SHMEM_OFI_TRANSMIT_DIAGNOSTICS=1
```

Use identical message sizes, provider settings, and work between put and
quiet for both completion modes. Keep diagnostics disabled for final
elapsed-time comparisons; the counters and clock reads have overhead.

## Diagnostic records

Each destroyed context emits a single `OFI_TRANSMIT_DIAGNOSTICS` record to
stderr on its owning PE. The default context emits its record at finalize.
`pe` and `ctx` identify each record; IDs can be reused after destruction.
These are local per-context totals, including internal library operations
using that context; no global aggregation or extra fabric traffic occurs.

`requested` shows the environment setting. `mode` distinguishes `transmit`,
`delivery-disabled`, and `delivery-provider-fallback`. A partial context
creation failure may report `uninitialized`. Check `mode=transmit` before
interpreting an enabled run as an optimized run.

| Fields | Meaning |
| --- | --- |
| `transmit_puts`, `transmit_bytes`, `transmit_fragments` | Unbuffered blocking puts routed to the direct endpoint; bytes count payload once per destination |
| `delivery_puts`, `delivery_bytes`, `delivery_fragments` | Equivalent blocking puts routed to the original endpoint when disabled or unsupported |
| `transmit_wait_ns` | Sum of direct-fragment submission, retry, and CQ-completion time; excludes lock acquisition and MR lookup |
| `delivery_submit_ns` | Sum of original-path bulk submission time; excludes the later source-completion wait |
| `sync_calls`, `empty_sync_calls` | Direct synchronization invocations and those posting no dirty-peer markers |
| `delivery_markers`, `marker_wait_ns` | Fenced zero-byte delivery markers and summed submission/completion time |
| `cq_polls`, `cq_empty_polls` | Direct CQ reads, including those during retries, and reads returning `FI_EAGAIN`; includes transmit and marker waits |
| `submit_retries` | Direct fragment/marker submissions returning `FI_EAGAIN` |
| `ordinary_quiet_calls`, `ordinary_quiet_ns` | Ordinary put-quiet calls and time draining bounce buffers and waiting on delivery counters; excludes direct synchronization and initial context-lock acquisition |
| `put_wait_calls`, `put_wait_ns` | Nonempty completion-token waits and their elapsed time, including ordinary quiet and any direct synchronization |

Times use the existing library clock (monotonic when available), are printed
in nanoseconds, and have the clock's actual resolution. They are summed local
durations, not application elapsed time or hardware timestamps.
`put_wait_ns` overlaps `ordinary_quiet_ns` and potentially `marker_wait_ns`;
do not sum all timing fields as a total. Completion-token waits can also
come from non-fetching vector atomics. Injected/bounce-buffered blocking
puts and ordinary NBI submissions are excluded from the put/byte/fragment
fields. The ordinary quiet fields include waits for those operations.

For a workload using only eligible blocking puts, the enabled run should
record transmit puts/fragments and no original-path bulk puts; the disabled
run should show the reverse and no direct CQ polls or delivery markers.
With diagnostics off, no diagnostic records, counters, extra diagnostic
locks, or clock reads are produced. Functional completion accounting still
operates in both modes.

The source has passed syntax-only static checks; it has not been linked or
executed because this workspace permits static analysis only. Runtime fabric
tracing should confirm `FI_TRANSMIT_COMPLETE | FI_COMPLETION` on each direct
blocking fragment and `FI_FENCE | FI_DELIVERY_COMPLETE | FI_COMPLETION` on
one zero-byte marker per dirty destination at synchronization. These direct
operations must use an endpoint with no bound write counter.
Concurrent `SHMEM_THREAD_MULTIPLE` calls and external device memory still
need runtime validation.
