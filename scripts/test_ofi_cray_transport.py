"""Executable checks of the live OFI transport, without a NIC or SOS rebuild.

Requires existing build/{src,mpp} headers and the configured OFI dependencies.
OFI_PREFIX can override the local libfabric installation used for compilation.
SOS_TEST_M4_SYNTAX=1 separately opts into fresh M4 expansion and syntax checks;
that check is skipped by default and requires permission to execute m4/compiler.
"""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
BASELINE_REF = "cc47ade0a0388304c47d2e8ec4fbc5b53de83b30"


class CrayTransportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = ROOT / (".ofi-cray-check-" + uuid.uuid4().hex)
        cls.directory.mkdir()
        cls.binaries = []
        cls.baseline_binaries = {}
        cls.env_binaries = []
        cls.environment = dict(os.environ, MPICH_CC="gcc", TMPDIR=str(cls.directory))
        prefix = Path(os.environ.get("OFI_PREFIX", "/opt/cray/libfabric/1.22.0"))
        cls.compiler = shlex.split(os.environ.get("CC", "mpicc"))
        command = cls.compiler + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-parameter", "-ffunction-sections", "-fdata-sections",
            "-Wl,--gc-sections", "-pthread",
        ]
        for directory in (
            ROOT / "build/src", ROOT / "src", ROOT / "build/mpp",
            ROOT / "mpp", ROOT / "include", prefix / "include",
            Path("/usr/include/libxml2"),
        ):
            command.append("-I" + str(directory))
        cls.compile_command = list(command)
        command += [
            str(ROOT / "scripts/fixtures/ofi_cray_transport_mock.c"),
            "-L" + str(prefix / "lib64"), "-lfabric", "-lhwloc", "-lxpmem",
        ]
        try:
            for name, definitions in (
                ("configured", []),
                ("ctx-lock-no-inject", ["-DUSE_CTX_LOCK", "-DDISABLE_OFI_INJECT"]),
            ):
                binary = cls.directory / name
                result = subprocess.run(
                    command + definitions + ["-o", str(binary)],
                    cwd=ROOT, env=cls.environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, timeout=90,
                )
                if result.returncode:
                    raise RuntimeError(name + ": transport fixture build failed:\n" +
                                       result.stdout + result.stderr)
                cls.binaries.append((name, binary))
            baseline = cls.directory / "baseline"
            baseline.mkdir()
            paths = subprocess.run(
                ["git", "ls-tree", "-r", "--name-only", BASELINE_REF, "src"],
                cwd=ROOT, capture_output=True, text=True, check=True,
            ).stdout.splitlines()
            for path in paths:
                if not path.endswith(".h") and path != "src/transport_ofi.c":
                    continue
                content = subprocess.run(
                    ["git", "show", BASELINE_REF + ":" + path], cwd=ROOT,
                    capture_output=True, check=True,
                ).stdout
                (baseline / Path(path).name).write_bytes(content)
            for name, definitions in (
                ("configured", []),
                ("ctx-lock-no-inject", ["-DUSE_CTX_LOCK", "-DDISABLE_OFI_INJECT"]),
            ):
                binary = cls.directory / ("baseline-" + name)
                result = subprocess.run(
                    cls.compiler + ["-I" + str(baseline)] +
                    command[len(cls.compiler):] +
                    definitions + ["-DSOS_MOCK_BASELINE", "-o", str(binary)],
                    cwd=ROOT, env=cls.environment,
                    capture_output=True, text=True, timeout=90,
                )
                if result.returncode:
                    raise RuntimeError(name + ": baseline fixture build failed:\n" +
                                       result.stdout + result.stderr)
                cls.baseline_binaries[name] = binary
            non_ofi = cls.directory / "non-ofi"
            non_ofi.mkdir()
            (non_ofi / "config.h").write_text(
                '#ifndef SOS_MOCK_CONFIG_H\n#define SOS_MOCK_CONFIG_H\n'
                '#include "' + str(ROOT / "build/src/config.h") + '"\n'
                '#undef USE_OFI\n#endif\n'
            )
            for name, extra_include in (
                ("ofi", []), ("non-ofi", ["-I" + str(non_ofi)]),
            ):
                binary = cls.directory / ("env-" + name)
                result = subprocess.run(
                    cls.compiler + extra_include +
                    cls.compile_command[len(cls.compiler):] +
                    [str(ROOT / "scripts/fixtures/ofi_cray_env_mock.c"),
                     "-lm", "-o", str(binary)],
                    cwd=ROOT, env=cls.environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, timeout=90,
                )
                if result.returncode:
                    raise RuntimeError(name + ": environment fixture build failed:\n" +
                                       result.stdout + result.stderr)
                cls.env_binaries.append((name, binary))
        except BaseException:
            shutil.rmtree(cls.directory)
            raise

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory)

    def run_case(self, case, status=0, diagnostic=None):
        for name, binary in self.binaries:
            with self.subTest(configuration=name, case=case):
                result = subprocess.run(
                    [str(binary), case], cwd=ROOT, env=self.environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True, timeout=10,
                )
                self.assertEqual(result.returncode, status,
                                 case + ":\n" + result.stdout + result.stderr)
                if diagnostic:
                    self.assertIn(diagnostic, result.stderr)

    def test_boundaries_flags_offsets_and_source_lifetime(self):
        self.run_case("boundaries")

    def test_mixed_peers_repeated_destinations_and_context_isolation(self):
        self.run_case("mixed")

    def test_peer_cache_eliminates_warm_single_peer_allocations(self):
        self.run_case("peer-cache")

    def test_conservative_controls_and_context_destruction(self):
        for case in ("controls", "shared-controls", "destroy"):
            with self.subTest(case=case):
                self.run_case(case)

    def test_disabled_paths_keep_inject_regular_and_bounce_behavior(self):
        self.run_case("disabled")

    def test_disabled_provider_traces_match_pre_investigation_source(self):
        for name, binary in self.binaries:
            for case in ("disabled", "disabled-controls", "disabled-startup"):
                with self.subTest(configuration=name, case=case):
                    outputs = []
                    for candidate in (self.baseline_binaries[name], binary):
                        result = subprocess.run(
                            [str(candidate), case], cwd=ROOT, env=self.environment,
                            capture_output=True, text=True, timeout=10,
                        )
                        self.assertEqual(result.returncode, 0,
                                         result.stdout + result.stderr)
                        outputs.append(result.stdout)
                    self.assertEqual(outputs[0], outputs[1])

    def test_startup_completion_configuration_is_opt_in(self):
        self.run_case("enabled-startup")

    def test_direct_experimental_helpers_reject_disabled_mode(self):
        for case in ("disabled-put-helper", "disabled-drain-helper", "disabled-control-helper"):
            self.run_case(case, status=1, diagnostic="SHMEM_OFI_CXI_CRAY_PUTS is disabled")

    def test_eagain_retries_count_each_operation_once(self):
        self.run_case("retries")

    def test_actual_environment_parser_non_ofi_rejection_and_precedence(self):
        clean = {key: value for key, value in self.environment.items()
                 if not key.startswith(("SHMEM_", "SMA_"))}
        shmem = "SHMEM_OFI_CXI_CRAY_PUTS"
        sma = "SMA_OFI_CXI_CRAY_PUTS"
        for configuration, binary in self.env_binaries:
            for name, overrides, enabled, provided in (
                ("unset", {}, 0, 0),
                ("off", {shmem: "0"}, 0, 1),
                ("on", {shmem: "1"}, 1, 1),
                ("alias-on", {sma: "1"}, 1, 1),
                ("shmem-wins", {shmem: "0", sma: "1"}, 0, 1),
            ):
                with self.subTest(configuration=configuration, case=name):
                    environment = dict(clean, **overrides)
                    result = subprocess.run(
                        [str(binary), str(enabled), str(provided)], cwd=ROOT,
                        env=environment, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, universal_newlines=True, timeout=10,
                    )
                    rejected = configuration == "non-ofi" and enabled
                    self.assertEqual(result.returncode, 1 if rejected else 0,
                                     result.stdout + result.stderr)
                    if rejected:
                        self.assertIn("requires an OFI build with the CXI provider",
                                      result.stderr)

    @unittest.skipUnless(os.environ.get("SOS_TEST_M4_SYNTAX") == "1",
                         "fresh M4/compiler execution requires explicit opt-in")
    def test_generated_signal_bindings_syntax(self):
        result = subprocess.run(
            ["m4", "-I" + str(ROOT / "bindings"),
             "-I" + str(ROOT / "build/bindings"), str(ROOT / "src/data_c.c4")],
            cwd=ROOT, env=self.environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, universal_newlines=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = self.directory / "data_c.c"
        generated.write_text(result.stdout)
        for name, definitions in (
            ("configured", []),
            ("ctx-lock-no-inject", ["-DUSE_CTX_LOCK", "-DDISABLE_OFI_INJECT"]),
        ):
            with self.subTest(configuration=name):
                result = subprocess.run(
                    [arg for arg in self.compile_command
                     if arg != "-Wl,--gc-sections"] +
                    definitions + ["-fsyntax-only", str(generated)],
                    cwd=ROOT, env=self.environment, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, universal_newlines=True, timeout=90,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_provider_validation_rejects_unsupported_configurations(self):
        for case in ("gate-valid", "gate-valid-multiple", "gate-valid-funneled"):
            self.run_case(case)
        for case, diagnostic in (
            ("gate-provider", "requires the CXI provider"),
            ("gate-context", "FI_CONTEXT or FI_CONTEXT2"),
            ("gate-context2", "FI_CONTEXT or FI_CONTEXT2"),
            ("gate-tx-context", "FI_CONTEXT or FI_CONTEXT2"),
            ("gate-rx-context2", "FI_CONTEXT or FI_CONTEXT2"),
            ("gate-localmr", "FI_MR_LOCAL or FI_MR_HMEM"),
            ("gate-hmem", "FI_MR_LOCAL or FI_MR_HMEM"),
            ("gate-inject", "inject_size >= 192"),
            ("gate-maxmsg", "max_msg_size >= 8192"),
            ("gate-thread-completion", "requires FI_THREAD_SAFE for SHMEM_THREAD_MULTIPLE"),
            ("gate-thread-domain", "requires FI_THREAD_SAFE for SHMEM_THREAD_MULTIPLE"),
        ):
            with self.subTest(case=case):
                self.run_case(case, status=1, diagnostic=diagnostic)

    def test_provider_errors_and_unknown_completions_are_rejected(self):
        for case, diagnostic in (
            ("error-payload", "OFI error"),
            ("error-flush", "OFI error"),
            ("error-kick", "OFI error"),
            ("error-wait", "OFI error"),
            ("error-counter", "counter reports an operation error"),
            ("error-cq", "OFI error"),
            ("bad-completion", "Unrecognized completion object"),
            ("foreign-marker", "Unrecognized completion object"),
            ("wrong-marker", "Unrecognized completion object"),
            ("oversize", "exceeds provider max_msg_size"),
        ):
            with self.subTest(case=case):
                self.run_case(case, status=1, diagnostic=diagnostic)


if __name__ == "__main__":
    unittest.main()
