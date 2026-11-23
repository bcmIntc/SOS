# OFI failed-post retry probes

In a separately built diagnostic library, set `SHMEM_OFI_RETRY_PROBE=1` on
every PE before initialization. It defaults to zero. Do not overwrite a
library pinned by an existing campaign; record the diagnostic library hash
and keep probe-on runs separate from performance measurements.

The probe emits `OFI retry probe:` records to stderr at retry attempts 1 and
16, capped at eight ordinary records per context. A final exhaustion or
non-EAGAIN error snapshot is always emitted, even after that cap. Source
buffers, retries, completion flags, progress calls and abort limits are
otherwise unchanged.

Records identify the PE/context, posting function/source line, target PE,
bytes, submitted flags and return code. They include issued/completed/error
counters, CQ read/event totals and the event count before progress, bounce
ownership/occupancy, group budget/state, delivery-epoch state and endpoint
sharing. For an internal group-flush marker, `pe=-1` means no inverse AV
lookup was attempted; `more_dest` is the provider address handle, not a
verified PE number. Marker writes contain zero bytes.

The existing "FI_MORE operation retry" error is selected by a nonzero group
limit, not by the failed post's actual FI_MORE flag. Limit 1 posts immediately.
Read `fi_more` and `flags` to distinguish a grouped payload, ordinary put/get/
atomic, delivery-epoch terminal write or group-flush marker. Counter goals
can include the currently unaccepted post; a nonzero remainder is not by
itself a leak or a source-ownership violation.

Enabled snapshots read provider counters and can perturb progress. Disabled
probes add no diagnostic counter reads or records. CQ totals count events
consumed by the existing CQ drain; the probe does not consume extra entries.
No diagnostic record proves hardware routing, target visibility or root cause.

Local CPU-only validation, without a production build or cluster launch:

```sh
python3.10 -m unittest discover -s scripts -p 'test_ofi*py' -v
```

The tests compile the production probe/retry/CQ-drain/group-flush functions
against provider mocks and check disabled behavior, bounded output, submitted
flags before retry mutation, progress/ownership snapshots, both retry limits
and unchanged fatal handling. Hardware qualification needs a fresh owned
allocation and the usual preflight and verified policy restoration.
