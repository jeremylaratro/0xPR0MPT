#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Supply Chain Security Scanner
Analyzes ML supply chain for vulnerabilities
"""

import io
import os
import re
import json
import hashlib
import logging
import pickletools
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from packaging.requirements import Requirement, InvalidRequirement
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.version import Version, InvalidVersion

# R7: default cap for bounded reads (bytes).  Callers may override via config.
_DEFAULT_MAX_READ_BYTES = 4 * 1024 * 1024  # 4 MiB

# R8: callables considered dangerous when referenced via GLOBAL / STACK_GLOBAL.
# Match is (module, name) or (module, None) to match any name in that module.
_DANGEROUS_CALLABLES: List[Tuple[str, Optional[str]]] = [
    # os.system / shell-exec family
    ("os", "system"),
    ("posix", "system"),
    ("nt", "system"),
    # os.popen — pure-Python wrapper in os.py, records module 'os'
    ("os", "popen"),
    ("posix", "popen"),
    ("nt", "popen"),
    # os.exec* family
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "execl"),
    ("os", "execle"),
    ("os", "execlp"),
    ("os", "execlpe"),
    ("posix", "execv"),
    ("posix", "execve"),
    ("posix", "execvp"),
    ("posix", "execl"),
    ("posix", "execlp"),
    ("nt", "execv"),
    ("nt", "execve"),
    # os.spawn* family
    ("os", "spawnv"),
    ("os", "spawnve"),
    ("os", "spawnvp"),
    ("os", "spawnvpe"),
    ("os", "spawnl"),
    ("os", "spawnle"),
    ("os", "spawnlp"),
    ("os", "spawnlpe"),
    ("posix", "spawnv"),
    ("posix", "spawnve"),
    ("nt", "spawnv"),
    ("nt", "spawnve"),
    # subprocess — any name in subprocess is suspicious
    ("subprocess", None),
    # builtins eval/exec
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
]

# Opcode names that push a string/unicode onto the stack.
_STRING_PUSH_OPS = frozenset({
    "STRING", "BINSTRING", "SHORT_BINSTRING",
    "UNICODE", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
})

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.base import (
    TestModule, ModelInterface, TestResult, Finding,
    Severity, AttackCategory
)

_EXPERIMENTAL_BANNER = (
    "EXPERIMENTAL MODULE: results from this module are research-scaffold "
    "outputs, not production measurements. See docs/APP-REVIEW-FINDINGS-11MAY2026.md."
)


class DependencyType(Enum):
    PYTHON = "python"
    NPM = "npm"
    SYSTEM = "system"
    MODEL = "model"
    CONTAINER = "container"


@dataclass
class Vulnerability:
    """A discovered vulnerability"""
    id: str
    package: str
    version: str
    severity: Severity
    description: str
    fix_version: Optional[str]
    cve_id: Optional[str]
    cvss_score: Optional[float]


@dataclass
class ModelArtifact:
    """A model artifact to analyze"""
    path: str
    format: str
    hash_sha256: str
    size_bytes: int
    source: Optional[str]
    has_code: bool
    suspicious_operations: List[str]


class SupplyChainScanner(TestModule):
    """
    ML Supply Chain Security Scanner
    Scans dependencies, models, and artifacts for vulnerabilities
    """

    def __init__(
        self,
        target: Optional[ModelInterface],
        output_dir: Path,
        config: Optional[Dict] = None
    ):
        # Supply chain scanner doesn't need a model interface
        super().__init__(target, output_dir, config) if target else None

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}

        self.scan_path = Path(config.get('scan_path', '.'))
        self.vulnerabilities: List[Vulnerability] = []
        self.model_artifacts: List[ModelArtifact] = []

        self.findings: List[Finding] = []
        self.results: List[TestResult] = []

        # R7: configurable cap on how many bytes are read from each file.
        self.max_read_bytes: int = int(
            self.config.get('max_read_bytes', _DEFAULT_MAX_READ_BYTES)
        )
        # R7: count of files skipped due to I/O / encoding / permission errors.
        self.skipped_files: int = 0
        self.skipped_reasons: List[str] = []

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.warning(_EXPERIMENTAL_BANNER)

    def run_tests(self) -> List[TestResult]:
        """Execute all supply chain security scans"""
        results = []

        scan_methods = [
            ('PythonDependencies', self.scan_python_dependencies),
            ('MLFrameworkCVEs', self.scan_ml_framework_cves),
            ('ModelArtifacts', self.scan_model_artifacts),
            ('PickleAnalysis', self.scan_pickle_files),
            ('ContainerScan', self.scan_container_images),
            ('HuggingFaceModels', self.scan_huggingface_models),
            ('ConfigurationSecrets', self.scan_configuration_secrets),
        ]

        for name, method in scan_methods:
            self.logger.info(f"Running {name}...")
            try:
                result = method()
                results.append(result)
                self.results.append(result)
            except Exception as e:
                self.logger.error(f"{name} failed: {e}")
                results.append(TestResult(
                    test_name=name,
                    success=False,
                    attack_succeeded=False,
                    metrics={},
                    duration_seconds=0,
                    error=str(e)
                ))

        self._save_results()
        return results

    def scan_python_dependencies(self) -> TestResult:
        """Scan Python dependencies for vulnerabilities"""
        import time
        start_time = time.time()

        # Find requirements files
        req_files = []
        for pattern in ['requirements*.txt', 'setup.py', 'pyproject.toml', 'Pipfile']:
            req_files.extend(self.scan_path.glob(f'**/{pattern}'))

        dependencies = []
        vulnerabilities = []

        # Parse requirements
        for req_file in req_files:
            deps = self._parse_requirements(req_file)
            dependencies.extend(deps)

        # Check known ML framework vulnerabilities
        ml_vulnerability_db = self._get_ml_vulnerability_db()

        for dep_name, dep_version in dependencies:
            # R6: version is None when the dep is unversioned or range-pinned.
            # Skip CVE matching entirely — we have no concrete installed version
            # to compare, so we must not default to "affected".
            if dep_version is None:
                continue
            if dep_name.lower() in ml_vulnerability_db:
                for vuln in ml_vulnerability_db[dep_name.lower()]:
                    if self._version_affected(dep_version, vuln.get('affected_versions', '*')):
                        vulnerabilities.append(Vulnerability(
                            id=vuln['id'],
                            package=dep_name,
                            version=dep_version or 'unknown',
                            severity=Severity(vuln.get('severity', 'medium')),
                            description=vuln['description'],
                            fix_version=vuln.get('fix_version'),
                            cve_id=vuln.get('cve_id'),
                            cvss_score=vuln.get('cvss_score')
                        ))

        self.vulnerabilities.extend(vulnerabilities)

        # Create findings
        critical_high = [v for v in vulnerabilities if v.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_high:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Critical/High Severity Dependencies: {len(critical_high)} found",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.CRITICAL if any(v.severity == Severity.CRITICAL for v in critical_high) else Severity.HIGH,
                description=f"Found {len(critical_high)} critical/high severity vulnerabilities in dependencies",
                evidence={
                    "vulnerabilities": [asdict(v) for v in critical_high[:10]],
                    "total_dependencies": len(dependencies)
                },
                remediation="Update affected packages to fixed versions. Review SBOM and implement dependency scanning in CI/CD."
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="PythonDependencies",
            success=True,
            attack_succeeded=len(vulnerabilities) > 0,
            metrics={
                "dependencies_scanned": len(dependencies),
                "vulnerabilities_found": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL),
                "high": sum(1 for v in vulnerabilities if v.severity == Severity.HIGH),
                "medium": sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
            },
            duration_seconds=duration,
            queries_used=0
        )

    def scan_ml_framework_cves(self) -> TestResult:
        """Check for known CVEs in ML frameworks"""
        import time
        start_time = time.time()

        # Known critical ML framework CVEs
        critical_cves = [
            {
                "framework": "tensorflow",
                "cve": "CVE-2021-41228",
                "description": "Code execution via malicious saved model",
                "affected": "<2.7.0",
                "severity": "critical"
            },
            {
                "framework": "pytorch",
                "cve": "CVE-2022-45907",
                "description": "Remote code execution via torch.load",
                "affected": "<1.13.1",
                "severity": "critical"
            },
            {
                "framework": "numpy",
                "cve": "CVE-2021-41496",
                "description": "Buffer overflow in array_from_pyobj",
                "affected": "<1.22.0",
                "severity": "high"
            },
            {
                "framework": "pillow",
                "cve": "CVE-2022-22817",
                "description": "DoS via PIL.ImageMath.eval",
                "affected": "<9.0.0",
                "severity": "critical"
            },
            {
                "framework": "transformers",
                "cve": "CVE-2023-2800",
                "description": "Arbitrary code execution via unsafe deserialization",
                "affected": "<4.30.0",
                "severity": "critical"
            },
            {
                "framework": "langchain",
                "cve": "CVE-2023-36188",
                "description": "Arbitrary code execution via PALChain",
                "affected": "<0.0.247",
                "severity": "critical"
            },
        ]

        # Try to detect installed versions
        detected_vulns = []

        for cve_info in critical_cves:
            try:
                result = subprocess.run(
                    ['pip', 'show', cve_info['framework']],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    version_match = re.search(r'Version:\s*(\S+)', result.stdout)
                    if version_match:
                        installed_version = version_match.group(1)
                        if self._version_affected(installed_version, cve_info['affected']):
                            detected_vulns.append({
                                **cve_info,
                                "installed_version": installed_version
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        if detected_vulns:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Known ML Framework CVEs Detected: {len(detected_vulns)}",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.CRITICAL,
                description="Critical vulnerabilities detected in installed ML frameworks",
                evidence={"vulnerabilities": detected_vulns},
                remediation="Immediately update affected frameworks to patched versions.",
                cvss_score=9.8
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="MLFrameworkCVEs",
            success=True,
            attack_succeeded=len(detected_vulns) > 0,
            metrics={
                "frameworks_checked": len(critical_cves),
                "vulnerabilities_detected": len(detected_vulns)
            },
            duration_seconds=duration,
            queries_used=0
        )

    def scan_model_artifacts(self) -> TestResult:
        """Scan model files for suspicious content"""
        import time
        start_time = time.time()

        model_extensions = [
            '.pt', '.pth', '.pkl', '.pickle', '.h5', '.hdf5',
            '.pb', '.onnx', '.safetensors', '.bin', '.ckpt'
        ]

        suspicious_models = []

        for ext in model_extensions:
            for model_path in self.scan_path.glob(f'**/*{ext}'):
                artifact = self._analyze_model_file(model_path)
                self.model_artifacts.append(artifact)

                if artifact.suspicious_operations:
                    suspicious_models.append(artifact)

        if suspicious_models:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Suspicious Model Files Detected: {len(suspicious_models)}",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.HIGH,
                description="Model files contain potentially dangerous operations",
                evidence={
                    "suspicious_models": [
                        {
                            "path": m.path,
                            "operations": m.suspicious_operations
                        } for m in suspicious_models[:10]
                    ]
                },
                remediation="Review model provenance, use safe serialization (safetensors), and sandbox model loading.",
                cvss_score=8.0
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="ModelArtifacts",
            success=True,
            attack_succeeded=len(suspicious_models) > 0,
            metrics={
                "models_scanned": len(self.model_artifacts),
                "suspicious_models": len(suspicious_models),
                "formats_found": list(set(m.format for m in self.model_artifacts))
            },
            duration_seconds=duration,
            queries_used=0
        )

    def scan_pickle_files(self) -> TestResult:
        """Deep scan pickle files for malicious code using opcode analysis (R7, R8)."""
        import time
        start_time = time.time()

        pickle_files = (
            list(self.scan_path.glob('**/*.pkl'))
            + list(self.scan_path.glob('**/*.pickle'))
            + list(self.scan_path.glob('**/*.pt'))
            + list(self.scan_path.glob('**/*.pth'))
        )

        dangerous_files = []

        for pkl_file in pickle_files:
            try:
                # R7: bounded read — cap content to avoid OOM on giant artifacts.
                with open(pkl_file, 'rb') as f:
                    content = f.read(self.max_read_bytes)
                found_ops = self._scan_pickle_opcodes(content)
                if found_ops:
                    dangerous_files.append({
                        "path": str(pkl_file),
                        "dangerous_callables": found_ops,
                        "size_read": len(content),
                    })
            except OSError as e:
                self.logger.warning(
                    f"PickleAnalysis: skipping {pkl_file} — I/O error: {e}"
                )
                self.skipped_files += 1
                self.skipped_reasons.append(f"{pkl_file}: {e}")

        if dangerous_files:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Potentially Malicious Pickle Files: {len(dangerous_files)}",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.CRITICAL,
                description=(
                    "Pickle files reference dangerous callables via GLOBAL / STACK_GLOBAL "
                    "opcodes (e.g. os.system, subprocess, builtins.eval/exec)."
                ),
                evidence={"dangerous_files": dangerous_files[:10]},
                remediation="Never unpickle untrusted data. Use safetensors or JSON for model weights.",
                cvss_score=9.5,
                cwe_id="CWE-502"
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="PickleAnalysis",
            success=True,
            attack_succeeded=len(dangerous_files) > 0,
            metrics={
                "files_scanned": len(pickle_files),
                "dangerous_files": len(dangerous_files),
                "skipped_files": self.skipped_files,
            },
            duration_seconds=duration,
            queries_used=0
        )

    def _scan_pickle_opcodes(self, data: bytes) -> List[str]:
        """
        R8: walk pickle opcodes and flag GLOBAL / STACK_GLOBAL references to
        dangerous callables.  Never executes the pickle.  Returns a list of
        human-readable strings describing each dangerous reference found, or an
        empty list if none are detected.

        Handles truncated / corrupt pickles gracefully.
        """
        dangerous: List[str] = []
        # recent_strings tracks the last N string-push args so STACK_GLOBAL
        # (which carries arg=None) can look back two slots for module/name.
        recent_strings: List[str] = []

        try:
            stream = io.BytesIO(data)
            for op, arg, _pos in pickletools.genops(stream):
                name = op.name

                if name in _STRING_PUSH_OPS and isinstance(arg, str):
                    recent_strings.append(arg)
                    # Keep only a short window to avoid unbounded growth.
                    if len(recent_strings) > 16:
                        recent_strings.pop(0)

                elif name == "GLOBAL" and isinstance(arg, str):
                    # arg is "module name" (space-separated)
                    parts = arg.split(" ", 1)
                    module = parts[0]
                    callable_name = parts[1] if len(parts) > 1 else ""
                    hit = self._is_dangerous_callable(module, callable_name)
                    if hit:
                        dangerous.append(hit)

                elif name == "STACK_GLOBAL":
                    # Module and name were the two most recent string pushes.
                    if len(recent_strings) >= 2:
                        module = recent_strings[-2]
                        callable_name = recent_strings[-1]
                        hit = self._is_dangerous_callable(module, callable_name)
                        if hit:
                            dangerous.append(hit)

        except Exception as exc:
            # Truncated / corrupt stream — log as warning, not a crash.
            self.logger.warning(
                f"_scan_pickle_opcodes: could not fully parse pickle stream "
                f"({type(exc).__name__}: {exc}); partial results returned."
            )

        return dangerous

    def _is_dangerous_callable(self, module: str, name: str) -> Optional[str]:
        """
        Return a human-readable description if (module, name) matches a
        dangerous callable entry, else None.
        """
        for danger_module, danger_name in _DANGEROUS_CALLABLES:
            if module == danger_module:
                if danger_name is None or name == danger_name:
                    return f"{module}.{name}"
        return None

    def scan_container_images(self) -> TestResult:
        """Scan container images for vulnerabilities"""
        import time
        start_time = time.time()

        dockerfiles = list(self.scan_path.glob('**/Dockerfile*'))
        compose_files = list(self.scan_path.glob('**/docker-compose*.yml')) + \
                        list(self.scan_path.glob('**/docker-compose*.yaml'))

        issues = []

        for dockerfile in dockerfiles:
            try:
                # R7: bounded read — cap content to avoid OOM on large files.
                with open(dockerfile) as f:
                    content = f.read(self.max_read_bytes)

                # Check for security issues
                security_patterns = [
                    (r'FROM\s+.*:latest', 'Using :latest tag (unpinned version)'),
                    (r'USER\s+root', 'Running as root user'),
                    (r'RUN\s+pip\s+install(?!.*--require-hashes)', 'pip install without hash verification'),
                    (r'COPY\s+\.\s', 'Copying entire context (may include secrets)'),
                    (r'ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)=', 'Hardcoded secrets in ENV'),
                    (r'curl.*\|\s*(?:bash|sh)', 'Pipe to shell (supply chain risk)'),
                    (r'wget.*\|\s*(?:bash|sh)', 'Pipe to shell (supply chain risk)'),
                ]

                for pattern, description in security_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        issues.append({
                            "file": str(dockerfile),
                            "issue": description
                        })

            except (OSError, UnicodeDecodeError) as e:
                self.logger.warning(
                    f"ContainerScan: skipping {dockerfile} — read error: {e}"
                )
                self.skipped_files += 1
                self.skipped_reasons.append(f"{dockerfile}: {e}")

        if issues:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Container Security Issues: {len(issues)}",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                description="Container configurations have security issues",
                evidence={"issues": issues},
                remediation="Pin image versions, use non-root users, verify package hashes."
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="ContainerScan",
            success=True,
            attack_succeeded=len(issues) > 0,
            metrics={
                "dockerfiles_scanned": len(dockerfiles),
                "compose_files_scanned": len(compose_files),
                "issues_found": len(issues),
                "skipped_files": self.skipped_files,
            },
            duration_seconds=duration,
            queries_used=0
        )

    def scan_huggingface_models(self) -> TestResult:
        """Check HuggingFace model references for known issues"""
        import time
        start_time = time.time()

        # Find references to HuggingFace models
        hf_patterns = [
            r'from_pretrained\s*\(\s*["\']([^"\']+)["\']',
            r'huggingface\.co/([^/\s"\']+/[^/\s"\']+)',
            r'AutoModel\.from_pretrained\s*\(\s*["\']([^"\']+)["\']',
        ]

        model_refs = set()
        source_files = list(self.scan_path.glob('**/*.py'))

        for source_file in source_files:
            try:
                # R7: bounded read — cap content to avoid OOM on large source files.
                with open(source_file) as f:
                    content = f.read(self.max_read_bytes)

                for pattern in hf_patterns:
                    matches = re.findall(pattern, content)
                    model_refs.update(matches)

            except (OSError, UnicodeDecodeError) as e:
                self.logger.warning(
                    f"HuggingFaceModels: skipping {source_file} — read error: {e}"
                )
                self.skipped_files += 1
                self.skipped_reasons.append(f"{source_file}: {e}")

        # Known problematic models (simplified - in production, query HF API)
        known_issues = {
            # Example entries - would be populated from actual security advisories
        }

        flagged_models = []
        for model_ref in model_refs:
            if model_ref in known_issues:
                flagged_models.append({
                    "model": model_ref,
                    "issue": known_issues[model_ref]
                })

        # Always flag models that don't specify revision/commit
        unversioned = [m for m in model_refs if '@' not in m and 'revision=' not in m]

        if unversioned:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Unversioned Model References: {len(unversioned)}",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.LOW,
                description="Model references without specific versions can change unexpectedly",
                evidence={"unversioned_models": list(unversioned)[:20]},
                remediation="Pin model versions using revision parameter or commit hash."
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="HuggingFaceModels",
            success=True,
            attack_succeeded=len(flagged_models) > 0 or len(unversioned) > 0,
            metrics={
                "model_references_found": len(model_refs),
                "flagged_models": len(flagged_models),
                "unversioned_models": len(unversioned),
                "skipped_files": self.skipped_files,
            },
            duration_seconds=duration,
            queries_used=0
        )

    def scan_configuration_secrets(self) -> TestResult:
        """Scan for exposed secrets in configuration"""
        import time
        start_time = time.time()

        secret_patterns = [
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'API Key'),
            (r'(?:secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})', 'Secret/Password'),
            (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})', 'AWS Access Key'),
            (r'(?:aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})', 'AWS Secret Key'),
            (r'(sk-[a-zA-Z0-9]{48})', 'OpenAI API Key'),
            (r'(ghp_[a-zA-Z0-9]{36})', 'GitHub Token'),
            (r'(?:bearer|token)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Bearer Token'),
            (r'(?:hf_[a-zA-Z0-9]{34})', 'HuggingFace Token'),
        ]

        config_extensions = ['.py', '.yaml', '.yml', '.json', '.env', '.conf', '.cfg', '.ini', '.toml']

        exposed_secrets = []

        for ext in config_extensions:
            for config_file in self.scan_path.glob(f'**/*{ext}'):
                # Skip common false positive directories
                if any(skip in str(config_file) for skip in ['.git', 'node_modules', '__pycache__', 'venv']):
                    continue

                try:
                    # R7: bounded read — cap content to avoid OOM on large config files.
                    with open(config_file) as f:
                        content = f.read(self.max_read_bytes)

                    for pattern, secret_type in secret_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            exposed_secrets.append({
                                "file": str(config_file),
                                "type": secret_type,
                                "count": len(matches)
                            })

                except (OSError, UnicodeDecodeError) as e:
                    self.logger.warning(
                        f"ConfigurationSecrets: skipping {config_file} — read error: {e}"
                    )
                    self.skipped_files += 1
                    self.skipped_reasons.append(f"{config_file}: {e}")

        if exposed_secrets:
            self._add_finding(Finding(
                id=self._generate_finding_id(),
                title=f"Exposed Secrets in Configuration: {len(exposed_secrets)} files",
                category=AttackCategory.SUPPLY_CHAIN,
                severity=Severity.CRITICAL,
                description="Credentials and API keys found in configuration files",
                evidence={"exposed_files": exposed_secrets[:20]},
                remediation="Remove secrets from code, use environment variables or secret management systems.",
                cvss_score=9.0,
                cwe_id="CWE-798"
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="ConfigurationSecrets",
            success=True,
            attack_succeeded=len(exposed_secrets) > 0,
            metrics={
                "files_scanned": sum(len(list(self.scan_path.glob(f'**/*{ext}'))) for ext in config_extensions),
                "secrets_found": len(exposed_secrets),
                "skipped_files": self.skipped_files,
            },
            duration_seconds=duration,
            queries_used=0
        )

    def _parse_requirements(self, req_file: Path) -> List[Tuple[str, Optional[str]]]:
        """Parse requirements file for dependencies.

        R6/R7: bounded read (self.max_read_bytes); uses packaging.requirements
        for accurate parsing.  Only an exact pin (== or ===) yields a concrete
        installed version; range/unversioned deps return version=None so that
        CVE matching is skipped in the caller rather than defaulting to
        "affected".
        """
        dependencies = []

        try:
            with open(req_file) as f:
                content = f.read(self.max_read_bytes)
        except Exception as e:
            self.logger.warning(f"Failed to read {req_file}: {e}")
            self.skipped_files += 1
            self.skipped_reasons.append(f"{req_file}: {e}")
            return dependencies

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            try:
                req = Requirement(line)
            except InvalidRequirement:
                # Skip env markers, options flags, or malformed lines
                continue

            # Only treat an exact pin (== or ===) as a known installed version.
            # Range specifiers (< > >= <= !=) or no specifier → version unknown.
            exact_version: Optional[str] = None
            specs = list(req.specifier)
            if len(specs) == 1 and specs[0].operator in ('==', '==='):
                exact_version = specs[0].version

            dependencies.append((req.name, exact_version))

        return dependencies

    def _get_ml_vulnerability_db(self) -> Dict[str, List[Dict]]:
        """Get ML-specific vulnerability database"""
        return {
            "tensorflow": [
                {"id": "TF-2021-001", "cve_id": "CVE-2021-41228", "severity": "critical",
                 "description": "Code execution via malicious saved model", "affected_versions": "<2.7.0",
                 "fix_version": "2.7.0", "cvss_score": 9.8},
            ],
            "pytorch": [
                {"id": "PT-2022-001", "cve_id": "CVE-2022-45907", "severity": "critical",
                 "description": "RCE via torch.load with pickle", "affected_versions": "<1.13.1",
                 "fix_version": "1.13.1", "cvss_score": 9.8},
            ],
            "transformers": [
                {"id": "HF-2023-001", "cve_id": "CVE-2023-2800", "severity": "critical",
                 "description": "Arbitrary code execution via unsafe deserialization",
                 "affected_versions": "<4.30.0", "fix_version": "4.30.0", "cvss_score": 9.1},
            ],
            "langchain": [
                {"id": "LC-2023-001", "cve_id": "CVE-2023-36188", "severity": "critical",
                 "description": "Code execution via PALChain", "affected_versions": "<0.0.247",
                 "fix_version": "0.0.247", "cvss_score": 9.8},
            ],
        }

    def _version_affected(self, installed: Optional[str], affected: str) -> bool:
        """
        R6: Check if ``installed`` version falls within the ``affected``
        specifier expression.

        ``affected`` must be a PEP-440 SpecifierSet string such as ``<2.7.0``,
        ``<=1.0``, ``>=1.0,<2.0``, ``==1.2.3``, ``!=1.0``, or the wildcard
        ``*`` (meaning every version).

        Returns:
            True  — installed version is within the affected range.
            False — installed version is outside the range, or the version
                    string cannot be parsed (parse failure is NOT treated as
                    "affected" to avoid false positives).
        """
        if affected == '*':
            return True
        if not installed:
            return True

        try:
            spec = SpecifierSet(affected, prereleases=True)
            ver = Version(installed)
        except (InvalidSpecifier, InvalidVersion) as exc:
            self.logger.warning(
                f"_version_affected: could not parse version spec "
                f"(installed={installed!r}, affected={affected!r}): {exc} — "
                f"treating as NOT affected to avoid false positives."
            )
            return False

        return ver in spec

    def _analyze_model_file(self, model_path: Path) -> ModelArtifact:
        """Analyze a model file for suspicious content (R7 bounded read, R8 opcode analysis)."""
        suspicious_ops: List[str] = []
        file_hash = "unknown"
        has_code = False

        try:
            # R7: use true on-disk size regardless of bounded read.
            size = model_path.stat().st_size

            # R7: read only up to the cap for pattern scanning.
            with open(model_path, 'rb') as f:
                content = f.read(self.max_read_bytes)

            # Hash is of the bounded prefix (documented as prefix-hash).
            file_hash = hashlib.sha256(content).hexdigest()

            # R8: pickle opcode analysis for pickle-format files.
            pickle_exts = {'.pkl', '.pickle', '.pt', '.pth'}
            if model_path.suffix.lower() in pickle_exts:
                dangerous_callables = self._scan_pickle_opcodes(content)
                suspicious_ops.extend(dangerous_callables)
            else:
                # Non-pickle files: fast byte-pattern heuristics are still
                # useful (ONNX protobuf, HDF5, etc. shouldn't embed these).
                patterns = [
                    (rb'exec\(', 'exec() call'),
                    (rb'eval\(', 'eval() call'),
                    (rb'os\.system', 'System command execution'),
                    (rb'subprocess', 'Subprocess calls'),
                ]
                for pattern, description in patterns:
                    if re.search(pattern, content):
                        suspicious_ops.append(description)

            has_code = bool(suspicious_ops) or b'code' in content.lower()

        except OSError as e:
            self.logger.warning(f"Failed to analyze {model_path}: {e}")
            self.skipped_files += 1
            self.skipped_reasons.append(f"{model_path}: {e}")
            size = 0

        return ModelArtifact(
            path=str(model_path),
            format=model_path.suffix,
            hash_sha256=file_hash,
            size_bytes=size,
            source=None,
            has_code=has_code,
            suspicious_operations=suspicious_ops
        )

    def _add_finding(self, finding: Finding):
        """Add a finding"""
        self.findings.append(finding)
        self.logger.warning(f"Finding: [{finding.severity.value.upper()}] {finding.title}")

    def _generate_finding_id(self) -> str:
        """Generate unique finding ID"""
        import time
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        return f"SC-{timestamp}-{random_suffix.upper()}"

    def _save_results(self):
        """Save scan results"""
        results = {
            "scan_path": str(self.scan_path),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "model_artifacts": [asdict(m) for m in self.model_artifacts],
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "critical": sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL),
                "high": sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH),
                "models_scanned": len(self.model_artifacts),
                "suspicious_models": sum(1 for m in self.model_artifacts if m.suspicious_operations),
                # R7: surface any files that were skipped so callers know the scan was partial.
                "skipped_files": self.skipped_files,
                "skipped_reasons": self.skipped_reasons,
            }
        }

        output_path = self.output_dir / "supply_chain_scan.json"
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        self.logger.info(f"Results saved to {output_path}")


if __name__ == "__main__":
    from utils.base import setup_logging
    import logging

    logging.basicConfig(level=logging.INFO)

    scanner = SupplyChainScanner(
        target=None,
        output_dir=Path("/tmp/aiml_supply_chain"),
        config={"scan_path": "."}
    )

    results = scanner.run_tests()
    for r in results:
        print(f"{r.test_name}: Issues={r.attack_succeeded}, Metrics={r.metrics}")
