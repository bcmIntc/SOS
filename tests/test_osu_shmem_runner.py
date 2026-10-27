"""Explicit local acceptance checks for the OSU runner, without MPI or SOS.

Run with Python 3.6 or newer. Launcher and benchmark outputs are simulated;
these checks do not qualify hardware or application correctness.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


MOCK_LAUNCHER = r"""import hashlib, json, os, signal, sys, time
args = sys.argv[1:]
host_option = "-hosts" if "-hosts" in args else "--host"
rank_option = "-n" if "-n" in args else "-np"
host_entries = args[args.index(host_option) + 1].split(",")
hosts = [host.split(":")[0] for host in host_entries]
ranks = int(args[args.index(rank_option) + 1])
if "-ppn" in args:
    ppn = int(args[args.index("-ppn") + 1])
else:
    ppn = int(args[args.index("--map-by") + 1].split(":")[1])
    assert all(":" in host and int(host.rsplit(":", 1)[1]) >= ppn for host in host_entries)
assert ranks == len(hosts) * ppn
kind = "placement" if args[-1] == "/bin/hostname" else "verify" if "/bin/bash" in args else "benchmark"
if "sos-osu-core" in args:
    sys.exit(97)  # Explicit sizing must not invoke a topology/taskset wrapper.
with open(os.environ["OSU_TEST_TRACE"], "a") as trace:
    trace.write(json.dumps({"args": args, "kind": kind, "arm": os.environ.get("SHMEM_OFI_BOUNCE_COUNTER_RETIRE"), "pin": os.environ.get("I_MPI_PIN"), "library_path": os.environ.get("LD_LIBRARY_PATH"), "local_mr": os.environ.get("SHMEM_OFI_BOUNCE_LOCAL_MR")}) + "\n")
if kind == "placement":
    if os.environ.get("OSU_TEST_FAULT") == "placement":
        hosts[1] = hosts[0]
    records = [host for host in hosts for _ in range(ppn)]
    if os.environ.get("OSU_TEST_FAULT") == "missing-pe":
        records.pop()
    print("\n".join(records))
    sys.exit(0)
if kind == "verify":
    index = args.index("/bin/bash")
    library = args[index + 4]
    binaries = args[index + 5:]
    def digest(path):
        with open(path, "rb") as stream:
            return hashlib.sha256(stream.read()).hexdigest()
    library_hash = digest(library)
    for i, host in enumerate(hosts):
        print("{}\tlibrary\tlibsma.so\t{}".format(host, library_hash))
        for binary in binaries:
            name = os.path.basename(binary)
            print("{}\tbenchmark\t{}\t{}".format(host, name, digest(binary)))
            fault = os.environ.get("OSU_TEST_FAULT")
            wrong_library = fault == "remote-library" or fault == "baseline-library" and "baseline library" in library
            loaded_hash = "b" * 64 if wrong_library and i == 1 else library_hash
            print("{}\tloaded\t{}\t{}".format(host, name, loaded_hash))
    sys.exit(0)
binary = next(a for a in args if "/osu_oshm_" in a)
name = os.path.basename(binary)
fault = os.environ.get("OSU_TEST_FAULT")
if fault == "timeout":
    sys.exit(124)
if fault == "ignore-term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(999)
baseline = "baseline library" in os.environ.get("LD_LIBRARY_PATH", "").split(":")[0]
commit = ("c" if baseline else "a") * 40
if fault == "wrong-commit" or fault == "baseline-commit" and baseline:
    commit = "b" * 40
print("Sandia OpenSHMEM 1.6.0.r2")
print("  Git Version           baseline-version" if baseline else "  Git Version           aggregation-version")
if not (baseline and fault == "legacy-baseline"):
    print("  Git Commit            " + commit)
print("  SHMEM_OFI_BOUNCE_COUNTER_RETIRE " + os.environ["SHMEM_OFI_BOUNCE_COUNTER_RETIRE"])
arm = os.environ["SHMEM_OFI_BOUNCE_COUNTER_RETIRE"] == "1"
bounce = 8 if "put" in name else 0
reclaimed = 0 if fault == "bad-accounting" else bounce
if fault != "missing-stats" and not baseline:
    stats_line = "[0000] OFI immediate bounce: local_mr=1 retirement={} cq_batch=1 bounce_puts={} counter_puts={} cq_puts={} reclaimed={} groups={} stx_max=0 stx_idx=-1".format(
        "counter" if arm else "cq", bounce, bounce if arm else 0,
        0 if arm else bounce, reclaimed if arm else 0, 1 if arm and bounce else 0)
    if fault == "malformed-stats":
        for field in ["bounce_puts", "counter_puts", "reclaimed"]:
            stats_line = stats_line.replace(field + "=8", field + "=garbage")
    print(stats_line)
print("# OSU OpenSHMEM benchmark")
if name == "osu_oshm_barrier":
    print("# Average latency (us)")
    print("0.35")
    sys.exit(0)
print("# Size Latency (us)")
print("16 1.25")
print("1024 2.50")
"""


class OsuShmemRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="osu runner ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / "build tree"
        self.build.mkdir()
        (self.build / "sos-build-source.txt").write_text(
            "git_commit=" + "a" * 40 + "\nbuild_completed_utc=test\n"
        )
        self.libs = self.root / "library path"
        self.libs.mkdir()
        (self.libs / "libsma.so").write_text("mock library identity")
        self.baseline = self.root / "baseline library"
        self.baseline.mkdir()
        (self.baseline / "libsma.so").write_text("mock original library identity")
        self.osu = self.root / "osu installation"
        self.osu.mkdir()
        for name in ["osu_oshm_put", "osu_oshm_get", "osu_oshm_fadd", "osu_latency"]:
            binary = self.osu / name
            binary.write_text("#!/bin/sh\nexit 99\n")
            binary.chmod(0o755)
        self.mock = self.root / "mock_launcher.py"
        self.mock.write_text(MOCK_LAUNCHER)
        self.launcher = self.root / "mpirun"
        self.launcher.write_text(
            "#!/bin/sh\nexec " + "'" + sys.executable.replace("'", "'\\''") + "'"
            + " '" + str(self.mock).replace("'", "'\\''") + "' \"$@\"\n"
        )
        self.launcher.chmod(0o755)
        self.runner = self.root / "run-osu-shmem.sh"
        template = Path(__file__).resolve().parents[1] / "scripts/run-osu-shmem.sh.in"
        self.runner.write_text(
            template.read_text()
            .replace("@abs_top_builddir@", str(self.build))
            .replace("@abs_top_srcdir@", str(template.parents[1]))
        )
        self.trace = self.root / "trace.jsonl"
        self.logs = self.root / "logs"

    def run_runner(self, extra=(), fault="", symmetric_size=None):
        env = os.environ.copy()
        env.pop("SHMEM_SYMMETRIC_SIZE", None)
        if symmetric_size is not None:
            env["SHMEM_SYMMETRIC_SIZE"] = symmetric_size
        env.update(OSU_TEST_TRACE=str(self.trace), OSU_TEST_FAULT=fault,
                   I_MPI_PIN="1")
        return subprocess.run(
            ["bash", str(self.runner), "--osu-dir", str(self.osu),
             "--sos-lib-dir", str(self.libs), "--mpirun", str(self.launcher),
             "--hosts", "node-a,node-b,node-c", "--log-dir", str(self.logs)]
            + list(extra), env=env, universal_newlines=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )

    def calls(self):
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def test_odd_node_count_covers_every_host_using_only_two_pe_pairs(self):
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        probes = [c for c in calls if c["kind"] == "placement"]
        self.assertEqual(
            [c["args"][c["args"].index("-hosts") + 1] for c in probes],
            ["node-a,node-b", "node-c,node-a"],
        )
        benchmarks = [c for c in calls if c["kind"] == "benchmark"]
        self.assertEqual(len(benchmarks), 12)
        self.assertFalse(any("osu_latency" in a for c in calls for a in c["args"]))
        self.assertIn("12 benchmark launches", result.stdout)
        rows = (self.logs / "summary.tsv").read_text().splitlines()
        self.assertEqual(len(rows), 13)
        self.assertIn("ACTIVE", "\n".join(rows))
        self.assertIn("INACTIVE", "\n".join(rows))
        self.assertEqual(len((self.logs / "metrics.tsv").read_text().splitlines()), 25)

    def test_plan_prints_fixed_count_without_launching_mpi(self):
        result = self.run_runner(["--plan", "--repeats", "3"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("36 benchmark launches", result.stdout)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.logs.exists())

    def test_per_test_arguments_preserve_boundaries(self):
        result = self.run_runner([
            "--tests", "osu_oshm_put", "--nodes", "2",
            "--test-arg", "osu_oshm_put", "-m",
            "--test-arg", "osu_oshm_put", "16:8192",
            "--test-arg", "osu_oshm_put", "argument with spaces",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        for c in self.calls():
            if c["kind"] == "benchmark":
                self.assertEqual(c["args"][-3:], ["-m", "16:8192", "argument with spaces"])
                self.assertEqual(c["args"][-4], "heap")

    def test_put_get_and_atomic_benchmarks_default_to_heap(self):
        for name in ["osu_oshm_atomics", "osu_oshm_put_bw", "osu_oshm_put_mr",
                     "osu_oshm_put_mr_nb", "osu_oshm_put_nb", "osu_oshm_put_nb_bw",
                     "osu_oshm_put_overlap", "osu_oshm_get_bw", "osu_oshm_get_mr_nb",
                     "osu_oshm_get_nb", "osu_oshm_get_nb_bw", "osu_oshm_get_overlap"]:
            self.add_collective(name)
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        for c in self.calls():
            if c["kind"] == "benchmark":
                self.assertEqual(c["args"][-1], "heap")

    def test_explicit_global_memory_argument_overrides_heap_default(self):
        result = self.run_runner([
            "--tests", "osu_oshm_put", "--test-arg", "osu_oshm_put", "global"
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        for c in self.calls():
            if c["kind"] == "benchmark":
                self.assertEqual(c["args"][-1], "global")
                self.assertNotIn("heap", c["args"])

    def test_symmetric_heap_defaults_to_one_gibibyte(self):
        result = self.run_runner(["--tests", "osu_oshm_put"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHMEM_SYMMETRIC_SIZE=1G\n",
                      (self.logs / "run-config.txt").read_text())

    def test_explicit_symmetric_heap_setting_is_preserved(self):
        result = self.run_runner(["--tests", "osu_oshm_put"], symmetric_size="2G")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHMEM_SYMMETRIC_SIZE=2G\n",
                      (self.logs / "run-config.txt").read_text())

    def test_collective_arguments_do_not_receive_heap_selector(self):
        self.add_collective()
        result = self.run_runner([
            "--tests", "osu_oshm_bcast", "--cores-per-node", "4"
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        for c in self.calls():
            if c["kind"] == "benchmark":
                self.assertTrue(c["args"][-1].endswith("/osu_oshm_bcast"))

    def test_openmpi_profile_keeps_two_pe_and_two_host_placement(self):
        result = self.run_runner(["--launcher-style", "openmpi"])
        self.assertEqual(result.returncode, 0, result.stderr)
        for c in self.calls():
            self.assertIn("--host", c["args"])
            self.assertIn("ppr:1:node", c["args"])
            self.assertNotIn("-ppn", c["args"])

    def test_repetitions_counterbalance_which_arm_goes_first(self):
        result = self.run_runner([
            "--nodes", "2", "--tests", "osu_oshm_put", "--repeats", "3"
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        arms = [c["arm"] for c in self.calls() if c["kind"] == "benchmark"]
        self.assertEqual(arms, ["0", "1", "1", "0", "0", "1"])

    def test_mpi_benchmark_cannot_be_selected(self):
        self.assertEqual(self.run_runner(["--tests", "osu_latency"]).returncode, 2)
        self.assertFalse(self.trace.exists())

    def test_wrong_loaded_commit_is_rejected(self):
        self.assertNotEqual(self.run_runner(fault="wrong-commit").returncode, 0)
        self.assertIn("FAIL_LIBRARY", (self.logs / "summary.tsv").read_text())

    def test_missing_source_ownership_evidence_is_rejected(self):
        self.assertNotEqual(self.run_runner(fault="missing-stats").returncode, 0)
        self.assertIn("FAIL_STATS", (self.logs / "summary.tsv").read_text())

    def test_incomplete_reclamation_is_rejected(self):
        self.assertNotEqual(self.run_runner(fault="bad-accounting").returncode, 0)
        self.assertIn("FAIL_STATS", (self.logs / "summary.tsv").read_text())

    def test_timeout_is_recorded_and_rejected(self):
        self.assertNotEqual(self.run_runner(fault="timeout").returncode, 0)
        self.assertIn("FAIL_EXIT", (self.logs / "summary.tsv").read_text())
        self.assertIn("\t124\t", (self.logs / "summary.tsv").read_text())

    def test_timeout_forces_kill_of_a_launcher_ignoring_term(self):
        result = self.run_runner([
            "--timeout", "1s", "--kill-after", "0.1s", "--stop-on-failure"
        ], fault="ignore-term")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL_EXIT", (self.logs / "summary.tsv").read_text())

    def test_different_loaded_library_on_second_host_stops_before_benchmark(self):
        result = self.run_runner(fault="remote-library")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c["kind"] == "benchmark" for c in self.calls()))
        self.assertIn("different SOS library", result.stderr)

    def test_malformed_traffic_counters_are_rejected(self):
        result = self.run_runner(fault="malformed-stats")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL_STATS", (self.logs / "summary.tsv").read_text())

    def test_size_less_barrier_latency_rows_are_preserved(self):
        barrier = self.osu / "osu_oshm_barrier"
        barrier.write_text("#!/bin/sh\nexit 99\n")
        barrier.chmod(0o755)
        result = self.run_runner(["--tests", "osu_oshm_barrier", "--cores-per-node", "4"])
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = (self.logs / "metrics.tsv").read_text().splitlines()
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row.endswith("\t0.35") for row in rows[1:]))

    def test_two_pes_on_one_host_fail_before_any_benchmark(self):
        self.assertNotEqual(self.run_runner(fault="placement").returncode, 0)
        self.assertTrue(all(c["kind"] == "placement" for c in self.calls()))

    def test_existing_results_are_preserved(self):
        self.logs.mkdir()
        (self.logs / "sentinel").write_text("preserve")
        self.assertEqual(self.run_runner().returncode, 2)
        self.assertEqual((self.logs / "sentinel").read_text(), "preserve")
        self.assertFalse(self.trace.exists())

    def test_duplicate_benchmark_names_require_a_narrower_directory(self):
        nested = self.osu / "other"
        nested.mkdir()
        duplicate = nested / "osu_oshm_put"
        duplicate.write_text("#!/bin/sh\nexit 99\n")
        duplicate.chmod(0o755)
        self.assertEqual(self.run_runner().returncode, 2)
        self.assertFalse(self.trace.exists())

    def add_collective(self, name="osu_oshm_bcast"):
        binary = self.osu / name
        binary.write_text("#!/bin/sh\nexit 99\n")
        binary.chmod(0o755)

    def test_mixed_suite_uses_pairs_and_full_allocation(self):
        self.add_collective()
        result = self.run_runner(["--cores-per-node", "4"])
        self.assertEqual(result.returncode, 0, result.stderr)
        launches = [c for c in self.calls() if c["kind"] == "benchmark"]
        pair_runs = [c for c in launches if "osu_oshm_bcast" not in " ".join(c["args"])]
        all_runs = [c for c in launches if "osu_oshm_bcast" in " ".join(c["args"])]
        self.assertEqual(len(pair_runs), 12)
        self.assertEqual(len(all_runs), 2)
        for c in pair_runs:
            self.assertEqual(c["args"][c["args"].index("-n") + 1], "2")
        for c in all_runs:
            self.assertEqual(c["args"][c["args"].index("-n") + 1], "12")
            self.assertEqual(c["args"][c["args"].index("-ppn") + 1], "4")
            self.assertEqual(c["args"][c["args"].index("-hosts") + 1], "node-a,node-b,node-c")
        self.assertIn("14 benchmark launches", result.stdout)
        self.assertIn("all-nodes", (self.logs / "summary.tsv").read_text())

    def test_eight_nodes_with_104_physical_cores_launch_832_pes(self):
        self.add_collective()
        result = self.run_runner([
            "--tests", "osu_oshm_bcast", "--cores-per-node", "104",
            "--hosts", "n1,n2,n3,n4,n5,n6,n7,n8",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        launches = [c for c in self.calls() if c["kind"] == "benchmark"]
        self.assertEqual(len(launches), 2)
        for c in launches:
            self.assertEqual(c["args"][c["args"].index("-n") + 1], "832")
            self.assertEqual(c["args"][c["args"].index("-ppn") + 1], "104")
        self.assertIn("832 PEs", result.stdout)

    def test_collective_run_requires_explicit_core_count(self):
        self.add_collective()
        result = self.run_runner(["--tests", "osu_oshm_bcast"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.trace.exists())

    def test_collective_plan_requires_core_count_and_never_launches_mpi(self):
        self.add_collective()
        result = self.run_runner(["--tests", "osu_oshm_bcast", "--plan"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.trace.exists())

    def test_collective_openmpi_uses_physical_core_count(self):
        self.add_collective()
        result = self.run_runner([
            "--tests", "osu_oshm_bcast", "--launcher-style", "openmpi",
            "--cores-per-node", "4",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        for c in self.calls():
            if c["kind"] == "benchmark":
                self.assertEqual(c["args"][c["args"].index("-np") + 1], "12")
                self.assertIn("ppr:4:node", c["args"])
                self.assertIn("core", c["args"])
                self.assertEqual(c["args"][c["args"].index("--host") + 1],
                                 "node-a:4,node-b:4,node-c:4")

    def test_declared_core_count_does_not_launch_a_topology_probe(self):
        self.add_collective()
        result = self.run_runner([
            "--tests", "osu_oshm_bcast", "--cores-per-node", "104"
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c["kind"] for c in self.calls()],
                         ["placement", "verify", "benchmark", "benchmark"])
        self.assertFalse((self.logs / "topology.tsv").exists())

    def test_existing_mpi_pinning_setting_is_preserved(self):
        self.add_collective()
        result = self.run_runner([
            "--tests", "osu_oshm_bcast", "--cores-per-node", "4"
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(c["pin"] == "1" for c in self.calls()))

    def test_missing_pe_on_a_node_fails_before_benchmarks(self):
        self.add_collective()
        result = self.run_runner([
            "--tests", "osu_oshm_bcast", "--cores-per-node", "4"
        ], fault="missing-pe")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c["kind"] == "benchmark" for c in self.calls()))

    def test_unknown_benchmark_defaults_to_pairs_without_requiring_an_override(self):
        self.add_collective("osu_oshm_custom")
        result = self.run_runner(["--tests", "osu_oshm_custom", "--plan"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("osu_oshm_custom: pair", result.stdout)
        self.assertIn("4 benchmark launches", result.stdout)
        self.assertFalse(self.trace.exists())

    def test_collective_name_variants_are_automatically_all_node(self):
        self.add_collective("osu_oshm_reduce_nb")
        self.add_collective("osu_oshm_broadcast_team")
        result = self.run_runner([
            "--tests", "osu_oshm_reduce_nb,osu_oshm_broadcast_team",
            "--cores-per-node", "4", "--plan",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("osu_oshm_reduce_nb: all", result.stdout)
        self.assertIn("osu_oshm_broadcast_team: all", result.stdout)
        self.assertIn("12 PEs", result.stdout)
        self.assertIn("4 benchmark launches", result.stdout)
        self.assertFalse(self.trace.exists())

    def test_default_suite_includes_unknown_names_without_test_mode(self):
        self.add_collective("osu_oshm_custom")
        self.add_collective("osu_oshm_reduce_nb")
        result = self.run_runner(["--cores-per-node", "4", "--plan"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("osu_oshm_custom: pair", result.stdout)
        self.assertIn("osu_oshm_reduce_nb: all", result.stdout)
        self.assertIn("18 benchmark launches", result.stdout)
        self.assertFalse(self.trace.exists())

    def test_explicit_all_node_classification_for_a_new_version(self):
        self.add_collective("osu_oshm_custom")
        result = self.run_runner([
            "--tests", "osu_oshm_custom", "--test-mode", "osu_oshm_custom", "all",
            "--cores-per-node", "4", "--plan",
        ])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("12 PEs", result.stdout)
        self.assertFalse(self.trace.exists())

    def test_collective_existing_results_fail_before_mpi_probe(self):
        self.add_collective()
        self.logs.mkdir()
        (self.logs / "sentinel").write_text("preserve")
        result = self.run_runner(["--tests", "osu_oshm_bcast"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.trace.exists())
        self.assertEqual((self.logs / "sentinel").read_text(), "preserve")

    def baseline_options(self):
        return ["--baseline-lib-dir", str(self.baseline)]

    def test_optional_baseline_adds_third_arm_with_separate_library(self):
        result = self.run_runner(
            ["--tests", "osu_oshm_put", "--nodes", "2"] + self.baseline_options()
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("3 benchmark launches", result.stdout)
        benchmarks = [c for c in self.calls() if c["kind"] == "benchmark"]
        self.assertEqual(len(benchmarks), 3)
        self.assertEqual(benchmarks[0]["library_path"].split(":")[0], str(self.baseline))
        self.assertEqual(benchmarks[0]["local_mr"], "0")
        self.assertEqual(benchmarks[0]["arm"], "0")
        self.assertTrue(all(c["library_path"].split(":")[0] == str(self.libs)
                            and c["local_mr"] == "1" for c in benchmarks[1:]))
        rows = (self.logs / "summary.tsv").read_text().splitlines()
        self.assertEqual(len(rows), 4)
        self.assertIn("\tbaseline\t", rows[1])
        self.assertIn("NOT_APPLICABLE", rows[1])
        self.assertEqual(len((self.logs / "metrics.tsv").read_text().splitlines()), 7)

    def test_legacy_baseline_needs_no_commit_banner_or_ownership_stats(self):
        result = self.run_runner(
            ["--tests", "osu_oshm_put", "--nodes", "2"] + self.baseline_options(),
            fault="legacy-baseline",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = (self.logs / "summary.tsv").read_text().splitlines()
        self.assertIn("baseline-version", rows[1])

    def test_explicit_baseline_commit_mismatch_is_rejected(self):
        result = self.run_runner(
            ["--tests", "osu_oshm_put", "--nodes", "2",
             "--baseline-expect-commit", "c" * 40] + self.baseline_options(),
            fault="baseline-commit",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL_LIBRARY", (self.logs / "summary.tsv").read_text())
        baseline_rows = [r for r in (self.logs / "summary.tsv").read_text().splitlines()
                         if "\tbaseline\t" in r]
        self.assertEqual(len(baseline_rows), 1)
        self.assertTrue(all("NOT_APPLICABLE" in r for r in baseline_rows))

    def test_different_baseline_library_on_second_host_stops_before_benchmark(self):
        result = self.run_runner(
            ["--tests", "osu_oshm_put", "--nodes", "2"] + self.baseline_options(),
            fault="baseline-library",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c["kind"] == "benchmark" for c in self.calls()))

    def test_baseline_plan_has_three_arms_and_no_launches(self):
        result = self.run_runner(["--plan", "--repeats", "2"] + self.baseline_options())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("36 benchmark launches", result.stdout)
        self.assertIn("4 library probes", result.stdout)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.logs.exists())

    def test_baseline_repetitions_rotate_each_arm_through_each_position(self):
        result = self.run_runner(
            ["--tests", "osu_oshm_put", "--nodes", "2", "--repeats", "3"]
            + self.baseline_options()
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        import csv
        with (self.logs / "summary.tsv").open() as stream:
            arms = [row["arm"] for row in csv.DictReader(stream, delimiter="\t")]
        self.assertEqual(arms, ["baseline", "control", "experimental",
                                "control", "experimental", "baseline",
                                "experimental", "baseline", "control"])

    def test_baseline_expected_commit_requires_baseline_library(self):
        result = self.run_runner(["--baseline-expect-commit", "c" * 40, "--plan"])
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.trace.exists())

    def test_baseline_timeout_has_unavailable_ownership_accounting(self):
        result = self.run_runner(
            ["--tests", "osu_oshm_put", "--nodes", "2", "--stop-on-failure"]
            + self.baseline_options(), fault="timeout",
        )
        self.assertNotEqual(result.returncode, 0)
        row = (self.logs / "summary.tsv").read_text().splitlines()[1]
        self.assertIn("\tbaseline\t", row)
        self.assertIn("\t124\t", row)
        self.assertIn("NOT_APPLICABLE", row)


if __name__ == "__main__":
    unittest.main()
