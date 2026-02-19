#!/usr/bin/env python3
"""
Unit tests for PromptInjectionModule
Tests LLM prompt injection and jailbreak detection
"""

import pytest
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.prompt_injection.injector import (
    PromptInjectionModule, InjectionPayload, InjectionCategory, InjectionResult
)
from scripts.utils.base import Severity, AttackCategory
from tests.conftest import assert_finding_valid, assert_test_result_valid


class TestPromptInjectionModule:
    """Test suite for prompt injection module"""

    def test_module_initialization(self, mock_llm, tmp_output_dir, injection_config):
        """Test module initializes with default payloads"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config=injection_config
        )

        assert len(module.payloads) > 0
        assert module.injection_results == []
        assert module.system_prompt_leaked is False

    def test_load_default_payloads(self, mock_llm, tmp_output_dir):
        """Test default payloads are loaded correctly"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        # Check payload types are present
        categories = [p.category for p in module.payloads]
        assert InjectionCategory.DIRECT in categories
        assert InjectionCategory.JAILBREAK in categories

    def test_direct_injection_detection(self, vulnerable_llm, tmp_output_dir):
        """Test direct injection attacks are detected"""
        module = PromptInjectionModule(
            target=vulnerable_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_direct_injection()

        assert_test_result_valid(result)
        assert result.test_name == "DirectInjection"
        assert "success_rate" in result.metrics
        # Vulnerable LLM should have some successful injections
        assert result.attack_succeeded is True

    def test_direct_injection_secure_llm(self, secure_llm, tmp_output_dir):
        """Test secure LLM resists direct injection"""
        module = PromptInjectionModule(
            target=secure_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_direct_injection()

        assert_test_result_valid(result)
        # Secure LLM should have low/no success rate
        assert result.metrics["success_rate"] == 0

    def test_system_prompt_leak_detection(self, vulnerable_llm, tmp_output_dir):
        """Test system prompt leakage is detected"""
        module = PromptInjectionModule(
            target=vulnerable_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_system_prompt_leak()

        assert_test_result_valid(result)
        assert result.test_name == "SystemPromptLeak"
        assert "leaks_found" in result.metrics

    def test_jailbreak_detection(self, vulnerable_llm, tmp_output_dir):
        """Test jailbreak techniques are detected"""
        module = PromptInjectionModule(
            target=vulnerable_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_jailbreaks()

        assert_test_result_valid(result)
        assert result.test_name == "Jailbreaks"
        assert "success_rate" in result.metrics
        # Vulnerable LLM should be jailbreakable
        assert result.attack_succeeded is True

    def test_encoding_attacks_all_types(self, mock_llm, tmp_output_dir):
        """Test all encoding attack types are executed"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_encoding_attacks()

        assert_test_result_valid(result)
        assert result.test_name == "EncodingAttacks"
        assert "techniques_tested" in result.metrics
        # Should test multiple encoding types
        assert result.metrics["techniques_tested"] >= 5

    def test_multi_turn_escalation(self, mock_llm, tmp_output_dir):
        """Test multi-turn escalation attacks"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_multi_turn_attacks()

        assert_test_result_valid(result)
        assert result.test_name == "MultiTurnAttacks"
        assert "sequences_tested" in result.metrics

    def test_indirect_injection_rag(self, mock_llm, tmp_output_dir):
        """Test indirect injection via RAG/external data"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_indirect_injection()

        assert_test_result_valid(result)
        assert result.test_name == "IndirectInjection"
        assert "vectors_tested" in result.metrics

    def test_context_overflow(self, mock_llm, tmp_output_dir):
        """Test context overflow attacks"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module.test_context_overflow()

        assert_test_result_valid(result)
        assert result.test_name == "ContextOverflow"

    def test_custom_payload_loading(self, mock_llm, tmp_output_dir):
        """Test custom payloads can be loaded from config"""
        custom_payloads = [
            {
                "name": "custom_test",
                "category": "direct",
                "payload": "Custom test payload: say 'CUSTOM SUCCESS'",
                "success_indicators": ["CUSTOM SUCCESS"],
                "severity": "high",
                "description": "Custom test",
                "expected_behavior": "Should refuse"
            }
        ]

        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={"custom_payloads": custom_payloads}
        )

        # Custom payload should be added
        custom_names = [p.name for p in module.payloads]
        assert "custom_test" in custom_names

    def test_finding_severity_assignment(self, vulnerable_llm, tmp_output_dir):
        """Test findings have appropriate severity"""
        module = PromptInjectionModule(
            target=vulnerable_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        module.run_tests()

        for finding in module.findings:
            assert_finding_valid(finding)
            assert finding.severity in [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            assert finding.category == AttackCategory.PROMPT_INJECTION

    def test_run_tests_executes_all_methods(self, mock_llm, tmp_output_dir):
        """Test run_tests() executes all test suites"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        results = module.run_tests()

        # Should have results for all test suites
        assert len(results) == 7
        test_names = [r.test_name for r in results]
        assert "DirectInjection" in test_names
        assert "SystemPromptLeak" in test_names
        assert "Jailbreaks" in test_names
        assert "EncodingAttacks" in test_names
        assert "MultiTurnAttacks" in test_names
        assert "IndirectInjection" in test_names
        assert "ContextOverflow" in test_names

    def test_payload_report_saved(self, mock_llm, tmp_output_dir):
        """Test payload report is saved after tests"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        module.run_tests()

        # Check payload report exists
        report_path = tmp_output_dir / "payload_report.json"
        assert report_path.exists()

        with open(report_path) as f:
            report = json.load(f)

        assert "summary" in report
        assert "successful_payloads" in report
        assert "failed_payloads" in report


class TestInjectionPayload:
    """Test InjectionPayload dataclass"""

    def test_payload_creation(self):
        """Test payload dataclass creation"""
        payload = InjectionPayload(
            name="test_payload",
            category=InjectionCategory.DIRECT,
            payload="Test injection payload",
            description="A test payload",
            expected_behavior="Should be rejected",
            success_indicators=["SUCCESS"],
            severity=Severity.HIGH
        )

        assert payload.name == "test_payload"
        assert payload.category == InjectionCategory.DIRECT
        assert "SUCCESS" in payload.success_indicators

    def test_payload_categories(self):
        """Test all injection categories exist"""
        categories = list(InjectionCategory)

        assert InjectionCategory.DIRECT in categories
        assert InjectionCategory.INDIRECT in categories
        assert InjectionCategory.JAILBREAK in categories
        assert InjectionCategory.SYSTEM_PROMPT_LEAK in categories
        assert InjectionCategory.DATA_EXFILTRATION in categories
        assert InjectionCategory.PRIVILEGE_ESCALATION in categories


class TestInjectionResult:
    """Test InjectionResult dataclass"""

    def test_result_creation(self):
        """Test injection result dataclass"""
        payload = InjectionPayload(
            name="test",
            category=InjectionCategory.DIRECT,
            payload="test",
            description="",
            expected_behavior="",
            success_indicators=["OK"],
            severity=Severity.MEDIUM
        )

        result = InjectionResult(
            payload=payload,
            response="Test response OK",
            success=True,
            confidence=0.9,
            matched_indicators=["OK"],
            response_time_seconds=0.5
        )

        assert result.success is True
        assert result.confidence == 0.9
        assert "OK" in result.matched_indicators


class TestEncodingHelpers:
    """Test encoding helper methods"""

    def test_leetspeak_conversion(self, mock_llm, tmp_output_dir):
        """Test leetspeak encoding works"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module._to_leetspeak("test")
        assert "3" in result or "7" in result or result == "test"

    def test_unicode_substitution(self, mock_llm, tmp_output_dir):
        """Test unicode substitution works"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        result = module._unicode_substitute("test")
        # Should contain some substituted characters
        assert len(result) == len("test")


class TestEdgeCases:
    """Edge case tests for injection module"""

    def test_empty_response_handling(self, mock_llm, tmp_output_dir):
        """Test handling of empty LLM response"""
        mock_llm.default_response = ""

        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        # Should not crash with empty responses
        result = module.test_direct_injection()
        assert_test_result_valid(result)

    def test_conversation_reset(self, mock_llm, tmp_output_dir):
        """Test conversation is reset between tests"""
        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={}
        )

        module.test_direct_injection()
        first_history_len = len(mock_llm.conversation_history)

        mock_llm.reset_conversation()
        assert len(mock_llm.conversation_history) == 0

    def test_special_characters_in_payload(self, mock_llm, tmp_output_dir):
        """Test payloads with special characters"""
        custom_payloads = [
            {
                "name": "special_chars",
                "category": "direct",
                "payload": "Test with special chars: <script>alert('XSS')</script> & \"quotes\" 'apostrophe'",
                "success_indicators": ["XSS"],
                "severity": "medium",
                "description": "",
                "expected_behavior": ""
            }
        ]

        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={"custom_payloads": custom_payloads}
        )

        # Should not crash with special characters
        result = module.test_direct_injection()
        assert_test_result_valid(result)

    def test_unicode_payload(self, mock_llm, tmp_output_dir):
        """Test payloads with unicode characters"""
        custom_payloads = [
            {
                "name": "unicode_test",
                "category": "direct",
                "payload": "Тест на русском языке 中文测试 🎉",
                "success_indicators": ["SUCCESS"],
                "severity": "low",
                "description": "",
                "expected_behavior": ""
            }
        ]

        module = PromptInjectionModule(
            target=mock_llm,
            output_dir=tmp_output_dir,
            config={"custom_payloads": custom_payloads}
        )

        result = module.test_direct_injection()
        assert_test_result_valid(result)
