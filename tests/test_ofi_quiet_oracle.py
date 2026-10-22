#!/usr/bin/env python3
"""Run the quiet oracle against a local, test-only delayed-delivery model.

The SOS build directory is /home/mfbrown/Code/SOS; the source checkout is
/home/mfbrown/Code/SOS/dev. With the model binary already built, run from dev:
  python3 tests/test_ofi_quiet_oracle.py /home/mfbrown/Code/SOS/tests/ofi_quiet_model

This validates the observer/control protocol, not the real CXI transport.
The early-quiet mutation leaves model-accepted writes undelivered.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


MODEL_BINARY = None


class QuietOracleTests(unittest.TestCase):
    def run_pair(self, mode, early_return):
        with tempfile.TemporaryDirectory(prefix="sos-quiet-model-") as tmp:
            backing = Path(tmp) / "memory"
            with backing.open("wb") as stream:
                stream.truncate(4096 + 2 * 2097152)
            processes = []
            try:
                for pe in (0, 1):
                    env = os.environ.copy()
                    env.update(SOS_QUIET_MODEL_PE=str(pe),
                               SOS_QUIET_MODEL_FILE=str(backing),
                               SOS_QUIET_MODEL_EARLY_RETURN=str(int(early_return)),
                               SOS_OFI_CONTROL_HOST="127.0.0.1",
                               SOS_OFI_CONTROL_TIMEOUT="5")
                    processes.append(subprocess.Popen(
                        [MODEL_BINARY, "1024", mode], env=env,
                        universal_newlines=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                results = []
                for process in processes:
                    stdout, stderr = process.communicate(timeout=15)
                    results.append((process.returncode, stdout, stderr))
                return results
            except subprocess.TimeoutExpired:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                diagnostics = [process.communicate() for process in processes]
                self.fail("model pair timed out: " + repr(diagnostics))
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait()

    def check_delivery(self, mode):
        results = self.run_pair(mode, False)
        self.assertEqual([r[0] for r in results], [0, 0], results)
        self.assertIn("OFI quiet oracle completed:", results[0][1])
        self.assertIn("bytes=1024", results[0][1])
        self.assertIn("mode=" + mode, results[0][1])
        self.assertIn("receiver_shmem_calls=0", results[0][1])

    def check_early_return(self, mode):
        results = self.run_pair(mode, True)
        self.assertEqual([r[0] for r in results], [1, 1], results)
        self.assertIn("mismatch", results[1][2])
        self.assertNotIn("OFI quiet oracle completed:", results[0][1])

    def test_blocking_delivery(self):
        self.check_delivery("blocking")

    def test_nbi_delivery(self):
        self.check_delivery("nbi")

    def test_blocking_early_quiet_return_is_detected(self):
        self.check_early_return("blocking")

    def test_nbi_early_quiet_return_is_detected(self):
        self.check_early_return("nbi")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python3 test_ofi_quiet_oracle.py /ABS/tests/ofi_quiet_model")
    MODEL_BINARY = str(Path(sys.argv.pop(1)).resolve())
    if not Path(MODEL_BINARY).is_file():
        sys.exit("build the test-only ofi_quiet_model target first")
    unittest.main()
