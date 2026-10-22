#!/usr/bin/env python3
"""Regression tests for build-helper orchestration with external tools replaced.

Run explicitly: python3 tests/test_ofi_vpath_workflow.py
These tests do not compile SOS or run MPI/CXI tests. They exercise the real
helper in separate source/build directories and inspect its command trace.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / "scripts/build-ofi-immediate.sh"
REBUILD_TEMPLATE = HELPER.with_name("rebuild-ofi.sh.in")


class VpathWorkflowTests(unittest.TestCase):
    def run_helper(self, existing=False, wrong_source=False, parent_path=False,
                   relative_build=False, configured_wrapper=False):
        with tempfile.TemporaryDirectory(prefix="sos-vpath-") as tmp:
            root = Path(tmp)
            source = root / "source checkout"
            build = source / "build"
            tools = root / "tools"
            (source / "scripts").mkdir(parents=True)
            build.mkdir()
            tools.mkdir()
            helper = source / "scripts/build-ofi-immediate.sh"
            helper.write_bytes(HELPER.read_bytes())
            trace = root / "trace.jsonl"
            recorder = tools / "record.py"
            recorder.write_text(
                "import json, os, sys\n"
                "with open(os.environ['VPATH_TEST_TRACE'], 'a') as f:\n"
                "    f.write(json.dumps([os.getcwd(), sys.argv[1:]]) + '\\n')\n")

            def traced_script(path, name):
                path.write_text(
                    "#!/bin/bash\n"
                    '"$VPATH_TEST_PYTHON" "$VPATH_TEST_RECORDER" '
                    + name + ' "$@"\n')
                path.chmod(0o755)

            traced_script(source / "autogen.sh", "autogen")
            traced_script(source / "configure", "configure")
            traced_script(tools / "make", "make")
            git = tools / "git"
            git.write_text(
                "#!/bin/sh\n"
                'case "$*" in\n'
                '  *"rev-parse --verify HEAD") printf "test-commit\\n" ;;\n'
                '  *"symbolic-ref --quiet --short HEAD") printf "test-branch\\n" ;;\n'
                "esac\n")
            git.chmod(0o755)
            if existing:
                configured_source = source
                if wrong_source:
                    configured_source = root / "other source"
                    configured_source.mkdir()
                elif parent_path:
                    configured_source = build / ".."
                (build / "Makefile").write_text(
                    "abs_top_srcdir = " + str(configured_source) + "\n")
                traced_script(build / "config.status", "config.status")
            env = os.environ.copy()
            env.update(PATH=str(tools) + os.pathsep + env["PATH"],
                       VPATH_TEST_TRACE=str(trace),
                       VPATH_TEST_PYTHON=sys.executable,
                       VPATH_TEST_RECORDER=str(recorder),
                       SOS_BUILD_JOBS="3")
            command = ["bash", str(helper),
                       str(build.relative_to(root)) if relative_build else str(build)]
            if configured_wrapper:
                (build / "scripts").mkdir()
                wrapper = build / "scripts/rebuild-ofi.sh"
                wrapper.write_text(
                    REBUILD_TEMPLATE.read_text()
                    .replace("@abs_top_srcdir@", str(source))
                    .replace("@abs_top_builddir@", str(build)))
                command = ["bash", str(wrapper)]
            result = subprocess.run(
                command,
                cwd=root, env=env,
                text=True, capture_output=True, timeout=30)
            calls = [json.loads(line) for line in trace.read_text().splitlines()
                     ] if trace.exists() else []
            record_path = build / "sos-build-source.txt"
            record = record_path.read_text() if record_path.exists() else ""
            return result, calls, record, str(source), str(build)

    def test_fresh_build_configures_from_build_directory(self):
        result, calls, record, source, build = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], [source, ["autogen"]])
        self.assertEqual(calls[1][0], build)
        self.assertEqual(calls[1][1][0], "configure")
        self.assertIn("--srcdir=" + source, calls[1][1])
        self.assertEqual(calls[-1], [build, ["make", "-j", "3", "ofi-regressions"]])
        self.assertIn("source_directory=" + source, record)
        self.assertIn("build_directory=" + build, record)

    def test_existing_build_rechecks_original_options_without_new_presets(self):
        result, calls, _, source, build = self.run_helper(existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [
            [source, ["autogen"]],
            [build, ["config.status", "--recheck"]],
            [build, ["config.status"]],
            [build, ["make", "-j", "3", "ofi-regressions"]],
        ])

    def test_configured_source_with_parent_component_is_accepted(self):
        result, _, _, _, _ = self.run_helper(existing=True, parent_path=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relative_build_path_is_resolved_from_callers_directory(self):
        result, calls, record, _, build = self.run_helper(relative_build=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[-1][0], build)
        self.assertIn("build_directory=" + build, record)

    def test_configured_wrapper_uses_substituted_source_and_build_paths(self):
        result, calls, _, source, build = self.run_helper(
            existing=True, configured_wrapper=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], [source, ["autogen"]])
        self.assertEqual(calls[-1], [build, ["make", "-j", "3", "ofi-regressions"]])

    def test_mismatched_source_stops_before_autogen_or_make(self):
        result, calls, record, _, _ = self.run_helper(
            existing=True, wrong_source=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("build directory uses source", result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(record, "")


if __name__ == "__main__":
    unittest.main()
