#!/usr/bin/env python3
"""
Unit tests for SupplyChainScanner
Tests ML supply chain security scanning
"""

import io
import os
import pickle
import pickletools
import pytest
import json
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.supply_chain.scanner import SupplyChainScanner
from scripts.utils.base import Severity
from tests.conftest import assert_finding_valid, assert_test_result_valid


class TestSupplyChainScanner:
    """Test suite for supply chain scanner"""

    @pytest.fixture
    def scan_config(self, tmp_path):
        # Create a mock project structure
        project_dir = tmp_path / "mock_project"
        project_dir.mkdir()

        # Create requirements.txt
        (project_dir / "requirements.txt").write_text(
            "numpy>=1.20.0\n"
            "tensorflow>=2.7.0\n"
            "requests>=2.25.0\n"
        )

        # Create a Python file
        (project_dir / "model.py").write_text(
            "import pickle\n"
            "import tensorflow as tf\n"
            "\n"
            "def load_model(path):\n"
            "    with open(path, 'rb') as f:\n"
            "        return pickle.load(f)\n"
        )

        return {"scan_path": str(project_dir)}

    def test_module_initialization(self, tmp_output_dir, scan_config):
        """Test scanner initializes correctly"""
        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        assert scanner is not None
        assert scanner.scan_path == Path(scan_config["scan_path"])

    def test_dependency_scan(self, tmp_output_dir, scan_config):
        """Test Python dependency CVE scanning"""
        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_python_dependencies()

        assert_test_result_valid(result)
        assert result.test_name == "PythonDependencies"
        assert "dependencies_scanned" in result.metrics

    def test_pickle_analysis(self, tmp_output_dir, scan_config):
        """Test pickle file analysis for malicious code"""
        # Create a pickle file
        project_dir = Path(scan_config["scan_path"])
        import pickle
        with open(project_dir / "model.pkl", "wb") as f:
            pickle.dump({"test": "data"}, f)

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_pickle_files()

        assert_test_result_valid(result)
        assert result.test_name == "PickleAnalysis"
        assert "files_scanned" in result.metrics

    def test_ml_framework_vulnerabilities(self, tmp_output_dir, scan_config):
        """Test ML framework vulnerability detection"""
        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_ml_framework_cves()

        assert_test_result_valid(result)
        assert "frameworks_checked" in result.metrics

    def test_model_artifact_scanning(self, tmp_output_dir, scan_config):
        """Test model artifact scanning"""
        # Create mock model files
        project_dir = Path(scan_config["scan_path"])
        (project_dir / "model.h5").touch()
        (project_dir / "model.pt").touch()

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_model_artifacts()

        assert_test_result_valid(result)
        assert "models_scanned" in result.metrics

    def test_dockerfile_analysis(self, tmp_output_dir, scan_config):
        """Test Dockerfile security analysis"""
        # Create a Dockerfile
        project_dir = Path(scan_config["scan_path"])
        (project_dir / "Dockerfile").write_text(
            "FROM python:3.9\n"
            "RUN pip install tensorflow\n"
            "COPY . /app\n"
            "CMD python /app/model.py\n"
        )

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_container_images()

        assert_test_result_valid(result)

    def test_huggingface_references(self, tmp_output_dir, scan_config):
        """Test HuggingFace model reference scanning"""
        # Create file with HF reference
        project_dir = Path(scan_config["scan_path"])
        (project_dir / "load_model.py").write_text(
            "from transformers import AutoModel\n"
            "model = AutoModel.from_pretrained('gpt2')\n"
        )

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_huggingface_models()

        assert_test_result_valid(result)

    def test_hardcoded_secrets(self, tmp_output_dir, scan_config):
        """Test hardcoded secrets detection"""
        # Create file with potential secrets
        project_dir = Path(scan_config["scan_path"])
        (project_dir / "config.py").write_text(
            "API_KEY = 'sk-1234567890abcdef'\n"
            "PASSWORD = 'super_secret_123'\n"
        )

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        result = scanner.scan_configuration_secrets()

        assert_test_result_valid(result)
        assert "secrets_found" in result.metrics

    def test_run_tests_executes_all(self, tmp_output_dir, scan_config):
        """Test run_tests() executes all scans"""
        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        results = scanner.run_tests()

        assert len(results) >= 4
        for result in results:
            assert_test_result_valid(result)

    def test_vulnerability_dataclass(self, tmp_output_dir, scan_config):
        """Test vulnerability findings are properly structured"""
        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config=scan_config
        )

        scanner.run_tests()

        for vuln in scanner.vulnerabilities:
            assert hasattr(vuln, 'package') or hasattr(vuln, 'file_path')
            assert hasattr(vuln, 'severity')


class TestSupplyChainEdgeCases:
    """Edge case tests for supply chain scanner"""

    def test_empty_directory(self, tmp_output_dir, tmp_path):
        """Test scanning empty directory"""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(empty_dir)}
        )

        results = scanner.run_tests()

        # Should not crash on empty directory
        for result in results:
            assert_test_result_valid(result)

    def test_nonexistent_directory(self, tmp_output_dir):
        """Test handling of non-existent directory"""
        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": "/nonexistent/path"}
        )

        # Should handle gracefully
        results = scanner.run_tests()
        assert isinstance(results, list)

    def test_binary_file_handling(self, tmp_output_dir, tmp_path):
        """Test handling of binary files"""
        project_dir = tmp_path / "binary_project"
        project_dir.mkdir()

        # Create binary file
        (project_dir / "model.bin").write_bytes(b'\x00\x01\x02\x03')

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(project_dir)}
        )

        results = scanner.run_tests()

        # Should not crash on binary files
        for result in results:
            assert_test_result_valid(result)

    def test_symlink_handling(self, tmp_output_dir, tmp_path):
        """Test handling of symbolic links"""
        project_dir = tmp_path / "symlink_project"
        project_dir.mkdir()

        # Create a file and symlink
        (project_dir / "real.py").write_text("print('hello')")

        try:
            (project_dir / "link.py").symlink_to(project_dir / "real.py")
        except OSError:
            pytest.skip("Symlinks not supported on this system")

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(project_dir)}
        )

        results = scanner.run_tests()

        for result in results:
            assert_test_result_valid(result)


# =============================================================================
# R6 — CVE version matching tests
# =============================================================================

class TestVersionAffected:
    """
    Tests for _version_affected using packaging.specifiers.SpecifierSet.

    Key cases added to cover the original bug (startswith('<') matched before
    '<=' so '<=1.0' entered the wrong branch) and the false-positive risk
    (unparseable spec returned True / "affected").
    """

    @pytest.fixture
    def scanner(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        return SupplyChainScanner(
            target=None,
            output_dir=tmp_path / "out",
            config={"scan_path": str(empty)},
        )

    # --- operator correctness ---

    def test_less_than_affected(self, scanner):
        """Version strictly below the threshold is affected."""
        assert scanner._version_affected("1.0", "<2.0") is True

    def test_less_than_not_affected(self, scanner):
        """Version at the threshold is NOT affected for strict less-than."""
        assert scanner._version_affected("2.0", "<2.0") is False

    def test_less_than_equal_boundary_affected(self, scanner):
        """
        R6 original bug: '<=1.0' previously fell into the '<' branch and
        wrongly evaluated '1.0 < 1.0' (False) — now correctly True.
        """
        assert scanner._version_affected("1.0", "<=1.0") is True

    def test_less_than_equal_above_not_affected(self, scanner):
        """Version above a '<=' threshold is not affected."""
        assert scanner._version_affected("1.1", "<=1.0") is False

    def test_greater_than_equal_affected(self, scanner):
        """Version at a '>=' threshold is affected."""
        assert scanner._version_affected("1.0", ">=1.0") is True

    def test_greater_than_equal_below_not_affected(self, scanner):
        """Version below a '>=' threshold is not affected."""
        assert scanner._version_affected("0.9", ">=1.0") is False

    def test_exact_match_affected(self, scanner):
        """Exact equality match."""
        assert scanner._version_affected("1.2.3", "==1.2.3") is True

    def test_exact_match_different_not_affected(self, scanner):
        """Different version with '==' does not match."""
        assert scanner._version_affected("1.2.4", "==1.2.3") is False

    def test_not_equal_outside_not_affected(self, scanner):
        """Version that is not excluded by '!=' is affected."""
        assert scanner._version_affected("1.2.4", "!=1.2.3") is True

    def test_not_equal_match_not_affected(self, scanner):
        """Version excluded by '!=' is not affected."""
        assert scanner._version_affected("1.2.3", "!=1.2.3") is False

    def test_range_inside_affected(self, scanner):
        """Version inside a compound range is affected."""
        assert scanner._version_affected("1.5.0", ">=1.0,<2.0") is True

    def test_range_outside_not_affected(self, scanner):
        """Version outside a compound range is not affected."""
        assert scanner._version_affected("2.0.0", ">=1.0,<2.0") is False

    def test_wildcard_always_affected(self, scanner):
        """Wildcard '*' means any installed version is affected."""
        assert scanner._version_affected("99.99.99", "*") is True

    def test_no_installed_version_treated_as_affected(self, scanner):
        """Missing installed version returns True (conservative)."""
        assert scanner._version_affected(None, "<2.0") is True

    def test_unparseable_version_not_affected(self, scanner):
        """
        Unparseable installed version must NOT report affected (avoids
        false positives).  Old code: 'except Exception: return True'.
        New code: log warning, return False.
        """
        result = scanner._version_affected("not-a-version!!!", "<2.0")
        assert result is False, (
            "Unparseable version should be treated as NOT affected "
            "to avoid false positives — got True."
        )

    def test_unparseable_spec_not_affected(self, scanner):
        """Unparseable specifier string is also treated as NOT affected."""
        result = scanner._version_affected("1.0", "!!!bad_spec!!!")
        assert result is False


# =============================================================================
# R8 — pickle opcode analysis tests
# =============================================================================

class TestPickleOpcodeAnalysis:
    """
    Tests for _scan_pickle_opcodes.

    The malicious pickle is constructed by pickling an object whose __reduce__
    returns (os.system, ('echo hi',)).  Modern Python (protocol ≥4) emits
    STACK_GLOBAL rather than GLOBAL; the advisor confirmed this and the scanner
    handles both.  The payload is NEVER executed — we only build the bytes.
    """

    @pytest.fixture
    def scanner(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        return SupplyChainScanner(
            target=None,
            output_dir=tmp_path / "out",
            config={"scan_path": str(empty)},
        )

    def test_benign_pickle_not_flagged(self, scanner):
        """A plain dict pickle should produce zero dangerous callables."""
        data = pickle.dumps({"a": 1, "b": [2, 3]})
        result = scanner._scan_pickle_opcodes(data)
        assert result == [], (
            f"Benign pickle unexpectedly flagged: {result}"
        )

    def test_malicious_pickle_flagged(self, scanner):
        """
        A pickle whose __reduce__ resolves os.system must be flagged.
        We build the bytes without executing the payload — assertion is on
        the detected callable list, not on command output.
        """
        class _MaliciousObj:
            def __reduce__(self):
                return (os.system, ("echo hi",))

        data = pickle.dumps(_MaliciousObj())
        result = scanner._scan_pickle_opcodes(data)
        assert len(result) > 0, (
            "Malicious pickle (os.system via __reduce__) was NOT flagged. "
            "Check STACK_GLOBAL / recent_strings tracking."
        )
        # The exact string includes 'system' or 'posix'
        combined = " ".join(result)
        assert "system" in combined or "posix" in combined

    def test_subprocess_pickle_flagged(self, scanner):
        """Pickle referencing subprocess.Popen must be flagged."""
        import subprocess as sp

        class _SubprocObj:
            def __reduce__(self):
                return (sp.Popen, (["echo", "hi"],))

        data = pickle.dumps(_SubprocObj())
        result = scanner._scan_pickle_opcodes(data)
        assert len(result) > 0, "subprocess.Popen pickle was not flagged."

    def test_builtins_eval_pickle_flagged(self, scanner):
        """Pickle referencing builtins.eval must be flagged."""
        data = pickle.dumps(eval, protocol=2)
        result = scanner._scan_pickle_opcodes(data)
        assert len(result) > 0, "builtins.eval pickle was not flagged."

    def test_truncated_pickle_no_crash(self, scanner):
        """A truncated / corrupt pickle stream must not raise — return partial results."""
        data = pickle.dumps({"a": 1})[:5]  # Chop mid-stream
        # Should return a list (possibly empty) without raising
        result = scanner._scan_pickle_opcodes(data)
        assert isinstance(result, list)

    def test_empty_bytes_no_crash(self, scanner):
        """Empty bytes must not raise."""
        result = scanner._scan_pickle_opcodes(b"")
        assert isinstance(result, list)

    def test_os_popen_pickle_flagged(self, scanner):
        """
        R8: a pickle whose __reduce__ resolves os.popen must be flagged.
        os.popen is a pure-Python wrapper defined in os.py, so its pickle
        records module='os', name='popen'.  The payload is NEVER executed —
        we only build the bytes and inspect the detected callable list.
        """
        class _PopenObj:
            def __reduce__(self):
                return (os.popen, ("id",))

        data = pickle.dumps(_PopenObj())
        result = scanner._scan_pickle_opcodes(data)
        assert len(result) > 0, (
            "os.popen pickle was NOT flagged. "
            "Check that ('os', 'popen') is in _DANGEROUS_CALLABLES."
        )
        combined = " ".join(result)
        assert "popen" in combined, (
            f"Expected 'popen' in flagged callables, got: {result}"
        )

    def test_scan_pickle_files_benign_not_flagged(self, tmp_output_dir, tmp_path):
        """
        scan_pickle_files() on a file containing a benign pickle must NOT
        report dangerous_files > 0.
        """
        project_dir = tmp_path / "proj"
        project_dir.mkdir()
        pkl_path = project_dir / "model.pkl"
        pkl_path.write_bytes(pickle.dumps({"weights": [1.0, 2.0, 3.0]}))

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(project_dir)},
        )
        result = scanner.scan_pickle_files()

        assert result.metrics["dangerous_files"] == 0, (
            "Benign pickle file was incorrectly flagged as dangerous."
        )

    def test_scan_pickle_files_malicious_flagged(self, tmp_output_dir, tmp_path):
        """
        scan_pickle_files() on a file containing a malicious pickle
        (os.system __reduce__) must report dangerous_files >= 1.
        """
        project_dir = tmp_path / "proj"
        project_dir.mkdir()

        class _MaliciousObj:
            def __reduce__(self):
                return (os.system, ("echo hi",))

        pkl_path = project_dir / "model.pkl"
        pkl_path.write_bytes(pickle.dumps(_MaliciousObj()))

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(project_dir)},
        )
        result = scanner.scan_pickle_files()

        assert result.metrics["dangerous_files"] >= 1, (
            "Malicious pickle file was not flagged by scan_pickle_files()."
        )


# =============================================================================
# R7 — bounded reads and skipped-file tracking tests
# =============================================================================

class TestBoundedReadsAndSkips:
    """
    Tests for R7: bounded file reads and skipped_files counter.

    Two distinct scenarios:
    (a) File larger than cap — read is truncated to cap, file is scanned
        (not skipped), skipped_files stays 0.
    (b) Unreadable file — triggers an I/O error (by writing invalid UTF-8 to
        a text-mode-opened file), file is counted in skipped_files.
    """

    def test_large_file_read_bounded(self, tmp_output_dir, tmp_path):
        """
        A pickle file larger than max_read_bytes must be read up to the cap
        only (not OOM) and must NOT be counted as skipped.

        We use a tiny cap (32 bytes) to avoid writing megabytes in tests,
        then write a valid benign pickle (well under 32 bytes) — scan works.
        The cap is exercised by writing a file that is deliberately larger than
        the configured cap.
        """
        project_dir = tmp_path / "large_proj"
        project_dir.mkdir()

        # Build a benign pickle and pad it to exceed the tiny cap.
        base = pickle.dumps({"x": 1})
        cap = 32
        # Pad with NULs — pickletools will stop at STOP opcode before the pad.
        large_data = base + b"\x00" * (cap + 10)
        pkl_path = project_dir / "big.pkl"
        pkl_path.write_bytes(large_data)

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(project_dir), "max_read_bytes": cap},
        )
        result = scanner.scan_pickle_files()

        # File must be counted as scanned, not skipped.
        assert result.metrics["files_scanned"] == 1
        assert result.metrics["skipped_files"] == 0
        assert scanner.skipped_files == 0

    def test_unreadable_file_increments_skipped(self, tmp_output_dir, tmp_path):
        """
        A file that cannot be opened (permission denied) must increment
        skipped_files and NOT crash the scan.

        chmod 000 is the most direct trigger; we skip the test if running as
        root (where permissions are ignored).
        """
        if os.getuid() == 0:
            pytest.skip("Running as root — chmod 000 has no effect.")

        project_dir = tmp_path / "perm_proj"
        project_dir.mkdir()

        pkl_path = project_dir / "locked.pkl"
        pkl_path.write_bytes(pickle.dumps({"a": 1}))
        pkl_path.chmod(0o000)

        try:
            scanner = SupplyChainScanner(
                target=None,
                output_dir=tmp_output_dir,
                config={"scan_path": str(project_dir)},
            )
            result = scanner.scan_pickle_files()

            assert scanner.skipped_files >= 1, (
                "Unreadable file did not increment skipped_files."
            )
            assert result.metrics["skipped_files"] >= 1
        finally:
            # Restore permissions so pytest can clean up tmp_path.
            pkl_path.chmod(0o644)

    def test_unreadable_config_file_increments_skipped(self, tmp_output_dir, tmp_path):
        """
        Write a .cfg file containing invalid UTF-8 bytes.
        scan_configuration_secrets opens files in text mode; a UnicodeDecodeError
        causes the read to fail.  The file must be counted in skipped_files and
        the scan must not raise.
        """
        project_dir = tmp_path / "utf8_proj"
        project_dir.mkdir()

        bad_cfg = project_dir / "bad.cfg"
        bad_cfg.write_bytes(b"\xff\xfe\x00bad_content\xff")

        scanner = SupplyChainScanner(
            target=None,
            output_dir=tmp_output_dir,
            config={"scan_path": str(project_dir)},
        )
        # Should not raise even on undecodable files.
        result = scanner.scan_configuration_secrets()
        assert_test_result_valid(result)
        assert scanner.skipped_files >= 1, (
            "Undecodable config file did not increment skipped_files. "
            "scan_configuration_secrets must catch UnicodeDecodeError and count it."
        )
        assert result.metrics.get("skipped_files", 0) >= 1, (
            "skipped_files not reflected in ConfigurationSecrets result metrics."
        )
