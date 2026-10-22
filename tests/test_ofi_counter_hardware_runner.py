"""Local runner acceptance tests; no MPI or fabric access.

The tests detect accepting a timed-out job, a missing completion marker, or an
error marker with zero hardware error evidence. Run explicitly with Python.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


MOCK = """#!/usr/bin/env python3
import os
import sys
case, size = sys.argv[-2:]
mode = os.environ.get("SOS_COUNTER_MOCK_MODE", "pass")
if mode == "timeout":
    sys.exit(124)
if mode == "missing-marker":
    sys.exit(0)
if mode != "missing-provider":
    for rank in [0, 1]:
        print(f"rank={rank} provider=cxi domain=cxi0 mr_mode=0x80 client_keys=1 test_limit=4 bytes={size} libfabric=1.22")
if case == "rebase":
    print(f"PASS rebase bytes={size} epochs=16 writes=288 rebases=71 receiver_payload_checks=272")
elif case == "preexisting-error":
    print("healthy baseline delivery and receiver payload check completed")
    print("preexisting hardware counter error observed before wait")
    print("rank=0 OFI put delivery counter reports 1 failed operation(s)")
    print("PASS preexisting-error counter_errors=1 cq_errors=0")
else:
    print("healthy baseline delivery and receiver payload check completed")
    print("revoked-key write accepted; entering delivery wait")
    print("rank=0 hardware CQ delivery error: err=13 prov_errno=5")
    count = 0 if mode == "zero-errors" else 1
    print(f"PASS delivery-error counter_errors=0 cq_errors={count}")
if mode == "nonzero":
    sys.exit(1)
"""


class CounterHardwareRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ofi counter runner ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "build tree"
        self.build.mkdir()
        self.record = "git_commit=test\nbuild_completed_utc=2026-10-22T00:00:00Z\n"
        (self.build / "sos-build-source.txt").write_text(self.record)
        template = Path(__file__).with_name("run-ofi-counter-hardware.sh.in")
        self.runner = self.root / "runner.sh"
        self.runner.write_text(
            template.read_text().replace("@abs_top_builddir@", str(self.build))
        )
        self.launcher = self.root / "mock-launcher"
        self.launcher.write_text(MOCK)
        self.launcher.chmod(0o755)
        self.binary = self.root / "ofi_counter_hardware"
        self.binary.write_text("#!/bin/sh\nexit 99\n")
        self.binary.chmod(0o755)
        self.logs = self.root / "logs"

    def run_runner(self, mode="pass"):
        env = os.environ.copy()
        env.update(SOS_OFI_LOG_DIR=str(self.logs), SOS_COUNTER_MOCK_MODE=mode)
        return subprocess.run(
            ["sh", str(self.runner), str(self.binary), str(self.launcher)],
            env=env, text=True, capture_output=True, timeout=10,
        )

    def test_all_five_cases_and_build_record_are_saved(self):
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = (self.logs / "summary.tsv").read_text().splitlines()
        self.assertEqual(len(rows), 6)
        self.assertEqual([row.split("\t")[:3] for row in rows[1:]], [
            ["rebase", "1024", "0"], ["rebase", "4096", "0"],
            ["rebase", "8192", "0"], ["preexisting-error", "1024", "0"],
            ["delivery-error", "1024", "0"],
        ])
        self.assertEqual(
            (self.logs / "sos-build-source.txt").read_text(), self.record
        )
        self.assertTrue((self.logs / "test-binary.sha256").is_file())

    def test_missing_marker_is_rejected_even_with_zero_exit(self):
        self.assertNotEqual(self.run_runner("missing-marker").returncode, 0)

    def test_timeout_is_rejected(self):
        self.assertNotEqual(self.run_runner("timeout").returncode, 0)
        self.assertIn("\t124\t", (self.logs / "summary.tsv").read_text())

    def test_provider_metadata_is_required_for_both_ranks(self):
        self.assertNotEqual(self.run_runner("missing-provider").returncode, 0)

    def test_nonzero_exit_is_rejected_even_with_pass_marker(self):
        self.assertNotEqual(self.run_runner("nonzero").returncode, 0)

    def test_delivery_error_requires_nonzero_hardware_evidence(self):
        self.assertNotEqual(self.run_runner("zero-errors").returncode, 0)
        self.assertTrue((self.logs / "delivery-error-1024.log").is_file())

    def test_existing_output_is_rejected(self):
        self.logs.mkdir()
        (self.logs / "sentinel").write_text("preserve")
        self.assertEqual(self.run_runner().returncode, 2)
        self.assertEqual((self.logs / "sentinel").read_text(), "preserve")

    def test_missing_build_record_stops_before_any_launch(self):
        (self.build / "sos-build-source.txt").unlink()
        self.assertEqual(self.run_runner().returncode, 2)
        self.assertFalse((self.logs / "summary.tsv").exists())

    def test_incomplete_build_record_stops_before_any_launch(self):
        (self.build / "sos-build-source.txt").write_text("git_commit=test\n")
        self.assertEqual(self.run_runner().returncode, 2)
        self.assertFalse((self.logs / "summary.tsv").exists())


if __name__ == "__main__":
    unittest.main()
