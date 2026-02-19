#!/usr/bin/env python3
"""
Unit tests for SupplyChainScanner
Tests ML supply chain security scanning
"""

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
