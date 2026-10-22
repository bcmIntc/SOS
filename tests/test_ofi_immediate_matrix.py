#!/usr/bin/env python3
"""Exercise the matrix runner locally, without MPI or the CXI provider.

Run with: python3 tests/test_ofi_immediate_matrix.py
Only the external cluster launcher is replaced; the real runner validates
the logs, exit statuses, skips and progression to the next negative case.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


RUNNER_TEMPLATE = Path(__file__).with_name("run-ofi-immediate-matrix.sh.in").resolve()
LAUNCHER = r'''
import os
from pathlib import Path
import sys

binary = Path(sys.argv[1]).name
if binary == "ofi_immediate":
    assert sys.argv[2:] == ["1024"]
    arm = os.environ["SHMEM_OFI_BOUNCE_COUNTER_RETIRE"]
    cq = os.environ["SHMEM_OFI_CQ_BATCH_SIZE"]
    owner = "counter" if arm == "1" else "cq"
    print("[0000] OFI immediate bounce: local_mr=1 retirement=" + owner +
          " cq_batch=" + cq + " bounce_puts=85 counter_puts=" +
          ("85" if arm == "1" else "0") + " cq_puts=" +
          ("0" if arm == "1" else "85") + " reclaimed=" +
          ("85" if arm == "1" else "0") + " groups=" +
          ("5" if arm == "1" else "0") + " stx_max=0 stx_idx=-1")
elif binary == "ofi_counter_init":
    if os.environ["SHMEM_OFI_BOUNCE_LOCAL_MR"] == "0":
        print("OFI_BOUNCE_COUNTER_RETIRE requires OFI_BOUNCE_LOCAL_MR=1")
        sys.exit(1)
    if os.environ["SHMEM_OFI_STX_MAX"] == "1":
        assert len(sys.argv) == 2
        mode = os.environ["MATRIX_TEST_STX"]
        if mode == "reject":
            print("OFI_BOUNCE_COUNTER_RETIRE requires an exclusive default TX queue")
            sys.exit(1)
        if mode in ("error", "timeout"):
            print("unrelated initialization failure")
            sys.exit(124 if mode == "timeout" else 2)
        topology = {
            "unavailable": "stx_max=0 stx_idx=-1",
            "shared": "stx_max=1 stx_idx=0",
            "missing": "",
            "missing-index": "stx_max=0",
            "pool-enabled": "stx_max=1 stx_idx=-1",
        }[mode]
        print("[0000] OFI immediate bounce: local_mr=1 retirement=counter"
              " cq_batch=8 bounce_puts=0 counter_puts=0 cq_puts=0"
              " reclaimed=0 groups=0 " + topology)
    else:
        assert sys.argv[2:] == ["multiple"]
        mode = os.environ["MATRIX_TEST_MULTIPLE"]
        if mode == "reject":
            print("OFI_BOUNCE_COUNTER_RETIRE requires SHMEM_THREAD_SINGLE")
            sys.exit(1)
        sys.exit(77 if mode == "downgrade" else 0)
else:
    sys.exit(2)
'''


class MatrixRunnerTests(unittest.TestCase):
    def run_matrix(self, stx, multiple="reject"):
        with tempfile.TemporaryDirectory(prefix="sos-matrix-test-") as tmp:
            root = Path(tmp)
            runner = root / "run-ofi-immediate-matrix.sh"
            runner.write_text(
                RUNNER_TEMPLATE.read_text()
                .replace("@abs_top_srcdir@", str(RUNNER_TEMPLATE.parents[1]))
                .replace("@abs_top_builddir@", str(root)))
            launcher = root / "launcher.py"
            launcher.write_text(LAUNCHER)
            env = os.environ.copy()
            env.update(SOS_OFI_LOG_DIR=str(root / "logs"),
                       MATRIX_TEST_STX=stx, MATRIX_TEST_MULTIPLE=multiple)
            result = subprocess.run(
                ["sh", str(runner), str(root / "ofi_immediate"), "1024",
                 sys.executable, str(launcher)],
                env=env, universal_newlines=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            multiple_recorded = (root / "logs/reject-multiple.log").is_file()
            return result, multiple_recorded

    def test_unavailable_stx_is_skipped_and_multiple_is_checked(self):
        result, recorded = self.run_matrix("unavailable")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SKIP:", result.stdout)
        self.assertTrue(recorded)
        self.assertIn("invalid configuration rejected:", result.stdout)

    def test_actual_shared_queue_rejection_remains_valid(self):
        result, recorded = self.run_matrix("reject")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SKIP:", result.stdout)
        self.assertTrue(recorded)

    def test_success_without_exclusive_topology_is_rejected(self):
        for mode in ("shared", "missing", "missing-index", "pool-enabled"):
            with self.subTest(mode=mode):
                result, recorded = self.run_matrix(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("FAIL:", result.stderr)
                self.assertFalse(recorded)

    def test_unrelated_failure_or_timeout_is_not_skipped(self):
        for mode in ("error", "timeout"):
            with self.subTest(mode=mode):
                result, recorded = self.run_matrix(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("SKIP:", result.stdout)
                self.assertFalse(recorded)

    def test_multiple_acceptance_still_fails_after_stx_skip(self):
        result, recorded = self.run_matrix("unavailable", "accept")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(recorded)
        self.assertIn("reject-multiple.log", result.stderr)

    def test_single_downgrade_is_reported_after_stx_skip(self):
        result, recorded = self.run_matrix("unavailable", "downgrade")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(recorded)
        self.assertIn("SKIP: MULTIPLE", result.stdout)


if __name__ == "__main__":
    unittest.main()
