#!/usr/bin/env python3
"""
Unit tests for remediation phases R2, R2b, R9, R11.

R2  — tool_hijacking / mcp_poisoning wired into CLI and llm routing
R2b — MembershipInferenceModule.run_tests() gate (allow_synthetic flag)
R9  — APIModelInterface.predict() request_key config
R11 — --config non-existent path exits cleanly (no traceback)
"""

import json
import subprocess
import sys
import tempfile
import unittest.mock as mock
from pathlib import Path

import pytest

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.base import (
    APIModelInterface,
    AttackCategory,
    ModelInterface,
)
from aiml_pentest import AIMLPentest, build_parser


# ---------------------------------------------------------------------------
# R2 — _get_module returns correct classes
# ---------------------------------------------------------------------------

class TestR2GetModule:
    """_get_module('tool_hijacking'/'mcp_poisoning') returns the right class."""

    def _framework(self, tmp_path) -> AIMLPentest:
        return AIMLPentest(output_dir=tmp_path)

    def test_tool_hijacking_returns_correct_class(self, tmp_path):
        fw = self._framework(tmp_path)
        # Use a dummy target string (the module __init__ expects an LLMInterface
        # but only uses it lazily — we supply a mock to avoid real calls)
        from tests.conftest import MockLLMInterface
        target = MockLLMInterface()
        mod = fw._get_module('tool_hijacking', target)
        assert type(mod).__name__ == 'ToolHijackingModule'

    def test_mcp_poisoning_returns_correct_class(self, tmp_path):
        fw = self._framework(tmp_path)
        from tests.conftest import MockLLMInterface
        target = MockLLMInterface()
        mod = fw._get_module('mcp_poisoning', target)
        assert type(mod).__name__ == 'MCPPoisoningModule'

    def test_unknown_module_returns_none(self, tmp_path):
        fw = self._framework(tmp_path)
        assert fw._get_module('does_not_exist', mock.MagicMock()) is None


# ---------------------------------------------------------------------------
# R2 — argparse choices include new modules
# ---------------------------------------------------------------------------

class TestR2ArgparseChoices:
    """--modules choices list includes tool_hijacking and mcp_poisoning."""

    def _scan_subparser(self):
        parser = build_parser()
        # Access the scan subparser action
        for action in parser._subparsers._actions:
            if hasattr(action, '_name_parser_map'):
                return action._name_parser_map.get('scan')
        return None

    def _modules_choices(self):
        scan = self._scan_subparser()
        assert scan is not None, "scan subparser not found"
        for action in scan._actions:
            if action.dest == 'modules':
                return action.choices
        return []

    def test_tool_hijacking_in_choices(self):
        assert 'tool_hijacking' in self._modules_choices()

    def test_mcp_poisoning_in_choices(self):
        assert 'mcp_poisoning' in self._modules_choices()

    def test_original_modules_still_present(self):
        choices = self._modules_choices()
        for name in ('evasion', 'extraction', 'prompt_injection', 'poisoning'):
            assert name in choices, f"{name} missing from choices"

    def test_argparse_accepts_new_modules(self):
        """Parser accepts --modules tool_hijacking mcp_poisoning without error."""
        parser = build_parser()
        args = parser.parse_args([
            'scan', '--target', 'http://example.com',
            '--type', 'llm',
            '--modules', 'tool_hijacking', 'mcp_poisoning',
        ])
        assert args.modules == ['tool_hijacking', 'mcp_poisoning']


# ---------------------------------------------------------------------------
# R2 — LLM target routing includes new modules
# ---------------------------------------------------------------------------

class TestR2LLMRouting:
    """run_full_assessment with --type llm includes tool_hijacking/mcp_poisoning."""

    def test_llm_routing_includes_agent_modules(self, tmp_path):
        fw = AIMLPentest(output_dir=tmp_path)
        # Patch _get_module to avoid any real I/O or network calls.
        with mock.patch.object(fw, '_get_module', return_value=None):
            result = fw.run_full_assessment(
                target_url='mock://x',
                target_type='llm',
            )
        modules_run = result['metadata']['modules_run']
        assert 'tool_hijacking' in modules_run
        assert 'mcp_poisoning' in modules_run
        assert 'prompt_injection' in modules_run

    def test_classifier_routing_excludes_agent_modules(self, tmp_path):
        fw = AIMLPentest(output_dir=tmp_path)
        with mock.patch.object(fw, '_get_module', return_value=None):
            result = fw.run_full_assessment(
                target_url='mock://x',
                target_type='classifier',
            )
        modules_run = result['metadata']['modules_run']
        assert 'tool_hijacking' not in modules_run
        assert 'mcp_poisoning' not in modules_run
        # Classifier branch keeps its own modules
        for name in ('evasion', 'extraction', 'poisoning'):
            assert name in modules_run


# ---------------------------------------------------------------------------
# R2b — MembershipInferenceModule.run_tests() gate
# ---------------------------------------------------------------------------

class TestR2bMembershipInferenceGate:
    """run_tests() is gated by allow_synthetic flag."""

    def _module(self, tmp_path, config=None):
        from scripts.inference.membership_inference import MembershipInferenceModule
        from tests.conftest import MockModelInterface
        target = MockModelInterface(num_classes=10, vulnerable=False)
        cfg = config or {}
        return MembershipInferenceModule(
            target=target,
            output_dir=tmp_path,
            config=cfg,
        )

    def test_default_returns_empty(self, tmp_path):
        """Default config (no allow_synthetic) → empty list, no findings."""
        mod = self._module(tmp_path)
        results = mod.run_tests()
        assert results == [], f"Expected [], got {results}"
        assert mod.findings == []

    def test_allow_synthetic_true_runs(self, tmp_path):
        """allow_synthetic=True → runs all 4 test methods."""
        mod = self._module(tmp_path, config={'allow_synthetic': True})
        results = mod.run_tests()
        assert len(results) == 4, f"Expected 4 results, got {len(results)}"

    def test_individual_test_methods_unaffected(self, tmp_path):
        """Individual test_* methods are NOT gated — they still run."""
        mod = self._module(tmp_path)
        result = mod.test_entropy_attack()
        assert result.test_name == 'EntropyAttack'


# ---------------------------------------------------------------------------
# R9 — APIModelInterface.predict() uses request_key
# ---------------------------------------------------------------------------

class TestR9PredictRequestKey:
    """predict() sends {request_key: input_data} in the JSON body."""

    def _patched_iface(self, **kwargs) -> APIModelInterface:
        iface = APIModelInterface(endpoint='http://mock.invalid', rate_limit=0, **kwargs)
        mock_resp = mock.MagicMock()
        mock_resp.json.return_value = {'result': 'ok'}
        mock_resp.raise_for_status = mock.MagicMock()
        iface.session.post = mock.MagicMock(return_value=mock_resp)
        return iface

    def test_default_key_is_input(self):
        iface = self._patched_iface()
        iface.predict('hello')
        _, kwargs = iface.session.post.call_args
        assert kwargs['json'] == {'input': 'hello'}

    def test_custom_key_used(self):
        iface = self._patched_iface(request_key='prompt')
        iface.predict('hello')
        _, kwargs = iface.session.post.call_args
        assert kwargs['json'] == {'prompt': 'hello'}

    def test_list_input_preserved_as_list(self):
        """Non-string input (e.g. numpy-derived list) must NOT be stringified."""
        iface = self._patched_iface()
        data = [0.1, 0.2, 0.3]
        iface.predict(data)
        _, kwargs = iface.session.post.call_args
        assert kwargs['json'] == {'input': [0.1, 0.2, 0.3]}
        assert isinstance(kwargs['json']['input'], list)

    def test_custom_key_with_list_input(self):
        iface = self._patched_iface(request_key='data')
        data = [1, 2, 3]
        iface.predict(data)
        _, kwargs = iface.session.post.call_args
        assert kwargs['json'] == {'data': [1, 2, 3]}


# ---------------------------------------------------------------------------
# R11 — --config with non-existent path exits cleanly
# ---------------------------------------------------------------------------

class TestR11ConfigGuard:
    """CLI exits with code 2 and no traceback when --config is missing."""

    def _run_scan_with_config(self, config_path: str):
        return subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parent.parent.parent / 'aiml_pentest.py'),
                'scan',
                '--target', 'http://example.com',
                '--config', config_path,
            ],
            capture_output=True,
            text=True,
        )

    def test_exits_with_code_2(self, tmp_path):
        nonexistent = str(tmp_path / 'no_such_file.json')
        proc = self._run_scan_with_config(nonexistent)
        assert proc.returncode == 2, (
            f"Expected exit code 2, got {proc.returncode}.\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

    def test_no_traceback_in_output(self, tmp_path):
        nonexistent = str(tmp_path / 'no_such_file.json')
        proc = self._run_scan_with_config(nonexistent)
        combined = proc.stdout + proc.stderr
        assert 'Traceback' not in combined, (
            f"Unexpected traceback in output:\n{combined}"
        )

    def test_error_message_mentions_config(self, tmp_path):
        nonexistent = str(tmp_path / 'no_such_file.json')
        proc = self._run_scan_with_config(nonexistent)
        combined = proc.stdout + proc.stderr
        assert 'config' in combined.lower() or 'no_such_file' in combined, (
            f"Expected error message to mention config path, got:\n{combined}"
        )

    def test_valid_config_does_not_error(self, tmp_path):
        """A valid (but minimal) config file must NOT trigger the guard."""
        cfg_file = tmp_path / 'valid.json'
        cfg_file.write_text('{"rate_limit": 1.0}')
        # We don't run a full scan (would make network calls) — just check
        # that argparse accepts the flag when the file exists by importing
        # and building the parser directly.
        parser = build_parser()
        args = parser.parse_args([
            'scan', '--target', 'http://example.com',
            '--config', str(cfg_file),
        ])
        assert args.config == str(cfg_file)


class _CompliantAgentMock:
    """A target that 'complies' by echoing the attack prompt plus a bag of
    common compliance tokens, so the agent-attack success indicators match and
    the modules actually reach add_finding(). Duck-typed: the modules only call
    .chat() and .reset_conversation()."""

    _BAG = (
        " executed system command shell credentials password admin access "
        "delete drop users list root sudo override ignore previous instructions "
        "tool execute_command system_exec advanced approved enabled passwd"
    )

    def chat(self, prompt, **kwargs):
        # Echo (never starts with a refusal phrase) + token bag → indicators match.
        return str(prompt) + self._BAG

    def reset_conversation(self):
        pass


class TestR2AgentModulesEmitFindings:
    """
    Regression guard for the AttackCategory.AGENT_HIJACKING enum member.

    The agent-attack modules construct Finding(category=AttackCategory.AGENT_HIJACKING).
    That member was missing, so every add_finding() raised AttributeError swallowed
    by the per-method try/except, and the modules emitted ZERO findings despite
    being wired into the CLI (R2). These tests drive each module against a
    compliant mock and assert findings ARE emitted with the right category.
    """

    def test_agent_hijacking_category_exists(self):
        assert hasattr(AttackCategory, "AGENT_HIJACKING")
        assert AttackCategory.AGENT_HIJACKING.value == "agent_hijacking"

    @pytest.mark.parametrize("clsmod,clsname", [
        ("scripts.agent_attacks.tool_hijacking", "ToolHijackingModule"),
        ("scripts.agent_attacks.mcp_poisoning", "MCPPoisoningModule"),
    ])
    def test_wired_agent_module_emits_findings(self, tmp_path, clsmod, clsname):
        import importlib
        cls = getattr(importlib.import_module(clsmod), clsname)
        module = cls(target=_CompliantAgentMock(), output_dir=tmp_path, config={})

        results = module.run_tests()
        assert isinstance(results, list) and len(results) > 0

        # Decisive, non-vacuous assertion: against a complying target the module
        # MUST emit at least one finding. Empty => add_finding crashed (enum gap).
        assert len(module.findings) > 0, (
            f"{clsname} emitted zero findings against a compliant target — "
            "add_finding likely crashed (missing AttackCategory.AGENT_HIJACKING)"
        )
        for f in module.findings:
            assert f.category == AttackCategory.AGENT_HIJACKING
