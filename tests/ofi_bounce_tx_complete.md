# TX-complete bounce-buffer prototype

`SHMEM_OFI_BOUNCE_TX_COMPLETE=1` is **opt-in and default-off**. It changes only
eligible off-node buffered blocking puts on the default context. SOS copies
the user source into a registered bounce slot and returns after an accepted
`FI_TRANSMIT_COMPLETE | FI_COMPLETION` post. That slot becomes reusable only
when its own CQ event is consumed, including out-of-order events.

**TX completion is not remote delivery.** A separate weak-destination bit
survives slot recycling and counter rebasing. Quiet issues and waits for
same-endpoint, same-peer zero-byte
`FI_FENCE | FI_DELIVERY_COMPLETE | FI_COMPLETION` markers, including for a
single weak put. Fence, control/signal and other incompatible/mixed operation
boundaries conservatively drain weak obligations. Teardown drains before
closing resources. EAGAIN cannot release an unaccepted source or acknowledge
a weak peer; permanent posting errors remain fatal.

## Initial scope and settings

Requires CXI, a host-only build, `SHMEM_THREAD_SINGLE`, the ordinary default
context, registered bounce sources and an exclusive TX queue. Unsupported
requested combinations fail at initialization, rather than silently claiming
an enabled route. The prototype enables existing CXI hybrid local-MR
registration itself; `SHMEM_OFI_BOUNCE_LOCAL_MR=1` is not additionally required.

Uniform settings for a separately qualified, isolated build are:

```sh
export SHMEM_OFI_BOUNCE_TX_COMPLETE=1
export SHMEM_OFI_STX_MAX=0 SHMEM_OFI_STX_AUTO=0
export SHMEM_OFI_PUT_MORE_BATCH=0 SHMEM_OFI_BOUNCE_COUNTER_RETIRE=0
export SHMEM_OFI_BOUNCE_NODE_BUDGET=0
export SHMEM_BOUNCE_SIZE=8192 SHMEM_MAX_BOUNCE_BUFFERS=128
```

The effective window is `(max(1024, injection_limit),
min(8192, bounce_size, provider_max_message)]` bytes and is printed at startup.
An empty window is rejected. Injection, direct/NBI, user-created contexts and
shared-memory-reachable peers retain strong paths. The topology exclusion
also covers local payloads too large for a CMA fast path.

FI_MORE (including batch size 1), counter source retirement, node budgets,
shared/automatic STX, HMEM, non-SINGLE threading, FI_CONTEXT/FI_CONTEXT2 and
mandatory FI_MR_LOCAL provider modes are excluded. Negotiation must support
TX CQ completion and fenced delivery CQ completion. Markers use a stable
registered symmetric address and dedicated context storage, not a bounce slot.

## CPU-only regressions

From the prototype source worktree, using Python 3.8+ and a C11 compiler:

```sh
PYTHONDONTWRITEBYTECODE=1 python3.10 scripts/test_ofi_bounce_tx_complete.py
PYTHONDONTWRITEBYTECODE=1 python3.10 scripts/test_ofi_bounce_pool_stats.py
PYTHONDONTWRITEBYTECODE=1 python3.10 scripts/test_ofi_retry_probe.py
```

`CC` can select another compiler. An existing configured tests Makefile also
provides `make -C tests check-ofi-bounce-tx-model PYTHON=python3.10`, without
building/linking production or using `TEST_RUNNER`. The driver creates and
removes scratch files inside the source worktree.

The provider fixture compiles the **actual production declarations/helpers**
extracted from `transport_ofi.h`, the counter header and the pure TX helper
header. It mocks only libfabric, registration/free-list storage and unrelated
disabled FI_MORE/progress infrastructure; it does not reimplement slot or
epoch logic. Coverage includes:

- User-source overwrite; delayed visibility; exact out-of-order slot reuse.
- Single, repeated and alternate destinations; empty/repeated quiet.
- Mixed delivery/TX traffic; accepted/rejected payloads and delivery markers.
- Pool pressure; local counter reset retaining weak state; teardown preamble.
- Fence/control/signal/get ordering under total-data-ordering 0/1 and
  compile-time FI_FENCE off/on.
- Disabled, injection, size/provider-limited, direct NBI and shared-peer routes.

The negative control mutates the production quiet helper to return early.
The same one-pass CPU observer that accepts real quiet must reject that
mutation after TX completion, with no target-side SHMEM progress.

## Public observation oracle and limits

`ofi_quiet_oracle BYTES blocking|nbi [WRITES]` now accepts `WRITES=1..17`
(default 17). Use `4096 blocking 1` to check the single-weak-put hazard, and
`4096 blocking 17` for pool pressure/reuse; verify 4096 is in the printed
effective window. Receiver observation occurs after TCP-only notification
and before any further target SHMEM call, barrier or polling for correctness.
The existing CPU-only `tests/test_ofi_quiet_oracle.py` tests both write counts
and deliberately early quiet; it validates the observer protocol, not CXI.

These models do not prove provider capability, DMA coherence, hardware
visibility, complete endpoint/MR destruction, thread safety, scalability or
performance. The destruction test executes the actual drain/assert preamble,
not provider resource closing. Hardware qualification requires an approved
allocation, an isolated install, mapped-library/source receipts and matched
enabled/disabled controls. Existing diagnostic jobs and pinned libraries
must remain untouched. No throughput improvement or automatic rollout is
claimed.
