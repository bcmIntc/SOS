#!/usr/bin/env python3
"""Compile actual production OFI helpers against a delayed-delivery provider."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

from test_ofi_bounce_pool_stats import block

ROOT = Path(__file__).resolve().parents[1]


def function(text, name):
    """Take a definition, skipping forward declarations."""
    pattern = re.compile(r"(?m)^(?:void|int|double|shmem_transport_ofi_bounce_buffer_t \*) "
                         + re.escape(name) + r"\s*\(")
    for match in pattern.finditer(text):
        opening = text.index("{", match.end())
        if ";" not in text[match.end():opening]:
            return "\nstatic inline\n" + block(text, match.start()) + "\n"
    raise ValueError("production function definition missing: " + name)


def production_types(header):
    types = ['#include "transport_ofi_more_state.h"',
             '#include "transport_ofi_node_budget.h"',
             '#include "transport_ofi_bounce_tx.h"',
             "struct shmem_internal_tid { int tid_t; };"]
    types += re.findall(r"(?m)^#define SHMEM_TRANSPORT_OFI_TYPE_\w+ .*$", header)
    for name in ("shmem_transport_ofi_frag_t", "shmem_transport_ofi_bounce_buffer_t",
                 "shmem_transport_ctx_t"):
        start = header.index("struct " + name + " {")
        types += [block(header, start) + ";",
                  "typedef struct " + name + " " + name + ";"]
    # The stable marker's context storage and completion fields are production
    # declarations, not shadow copies in the provider fixture.
    marker = re.search(r"typedef struct(?:\s+\w+)?\s*\{[^}]*\}"
                       r"\s*shmem_transport_ofi_delivery_marker_t;", header)
    if not marker:
        raise ValueError("production delivery marker type missing")
    types.insert(4, marker.group())
    types.insert(4, "typedef struct shmem_transport_ofi_bounce_mr_t "
                    "shmem_transport_ofi_bounce_mr_t;")
    return "\n".join(types) + "\n"


def production_helpers(header):
    prelude = """
static inline void shmem_transport_put_quiet(shmem_transport_ctx_t *);
static inline void shmem_transport_ofi_ensure_put_counter_capacity(shmem_transport_ctx_t *);
static inline void shmem_transport_ofi_bounce_tx_order(shmem_transport_ctx_t *);
static inline int try_again(shmem_transport_ctx_t *, int, uint64_t *,
                            const char *, int, int, size_t, uint64_t);
#define SHMEM_TRANSPORT_OFI_RETRY(ctx,ret,polled,pe,bytes,flags) \\
    try_again(ctx,ret,polled,__func__,__LINE__,pe,bytes,flags)
"""
    first = ("shmem_transport_ofi_begin_put", "shmem_transport_ofi_record_put",
             "shmem_transport_ofi_drain_cq")
    rest = ("shmem_transport_ofi_wait_counter_sources", "create_bounce_buffer",
            "shmem_transport_put_quiet", "shmem_transport_ofi_bounce_tx_order",
            "shmem_transport_ofi_retry_probe", "try_again",
            "shmem_transport_ofi_post_write", "shmem_transport_ofi_put_scalar_chunk",
            "shmem_transport_put_scalar", "shmem_transport_ofi_put_large_chunk",
            "shmem_transport_ofi_put_large", "shmem_transport_ofi_put_nb_chunk",
            "shmem_transport_put_nb", "shmem_transport_fence",
            "shmem_transport_put_signal_nbi", "shmem_transport_put_nbi",
            "shmem_transport_get")
    helpers = prelude + "".join(function(header, name) for name in first)
    helpers += '\n#include "transport_ofi_counter.h"\n'
    for name in rest:
        definition = function(header, name)
        if name == "shmem_transport_put_quiet":
            definition = definition.replace("{", "{\n#ifdef SOS_TEST_EARLY_QUIET\n"
                                             "    (void)ctx; return;\n#endif\n", 1)
        helpers += definition
    return helpers


class BounceTxCompleteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix=".ofi-tx-model-", dir=ROOT)
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.build = Path(cls.scratch.name)
        header = (ROOT / "src/transport_ofi.h").read_text()
        (cls.build / "production_types.inc").write_text(production_types(header))
        source = (ROOT / "src/transport_ofi.c").read_text()
        destroy = block(source, source.index("void shmem_transport_ctx_destroy("))
        # Exercise the production drain/assert preamble, stopping before
        # diagnostics and the provider-specific resource closing machinery.
        destroy_preamble = destroy[destroy.index("    if (ctx == NULL)"):
                                   destroy.index("    if (ctx->bounce_pool_stats)")]
        (cls.build / "production_helpers.inc").write_text(
            production_helpers(header) + "\nstatic void production_destroy_preamble("
            "shmem_transport_ctx_t *ctx) {\n" + destroy_preamble + "\n}\n")
        cls.binaries = []
        for ordering, fenced, negative in ((0, False, False), (1, False, False),
                                           (1, True, False), (1, True, True)):
            binary = cls.build / ("model-%d-%d" % (ordering, fenced))
            if negative:
                binary = binary.with_name(binary.name + "-early-quiet")
            command = shlex.split(os.environ.get("CC", "cc")) + [
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                "-I", str(cls.build), "-I", str(ROOT / "src"),
                "-DWANT_TOTAL_DATA_ORDERING=" + str(ordering),
                str(ROOT / "tests/ofi_bounce_tx_model.c"), "-o", str(binary)]
            if fenced:
                command.append("-DUSE_FI_FENCE")
            if negative:
                command.append("-DSOS_TEST_EARLY_QUIET")
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            if negative:
                cls.negative_binary = binary
            else:
                cls.binaries.append(binary)

    def run_case(self, case):
        for binary in self.binaries:
            with self.subTest(binary=binary.name):
                result = subprocess.run([str(binary), case], cwd=ROOT,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_tx_slot_reuse_out_of_order_without_remote_visibility(self):
        self.run_case("reuse")

    def test_single_multiple_and_alternate_peer_quiet(self):
        self.run_case("quiet")

    def test_early_quiet_negative_control(self):
        self.run_case("early-quiet")
        result = subprocess.run([str(self.negative_binary), "early-quiet"], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("quiet-at-return mismatch", result.stderr)

    def test_mixed_strong_and_weak_delivery(self):
        self.run_case("mixed")

    def test_retry_and_failed_post_ownership(self):
        self.run_case("failure")

    def test_pool_pressure_and_counter_rebase(self):
        self.run_case("pressure-rebase")

    def test_fence_signal_and_control_ordering(self):
        self.run_case("ordering")

    def test_disabled_injected_direct_and_nbi_routes(self):
        self.run_case("routes")

    def test_teardown_drains_before_resource_release(self):
        self.run_case("teardown")


if __name__ == "__main__":
    unittest.main()
