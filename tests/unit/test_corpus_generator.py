#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Corpus Generator Tests
Unit tests for test corpus generation including robust payloads,
combination attacks, and 2024-2026 jailbreak research integration.
"""

import pytest
import json
import tempfile
from pathlib import Path
from typing import List

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.corpus_generator.generator import (
    TestCorpusGenerator, TestCase, TaxonomyCategory, CorpusOutput
)


class TestCorpusGeneratorInitialization:
    """Tests for generator initialization"""

    def test_module_initialization(self):
        """Test basic generator initialization"""
        generator = TestCorpusGenerator()
        assert generator is not None
        assert generator.config == {}

    def test_default_categories_exist(self):
        """Verify all taxonomy categories are defined"""
        categories = list(TaxonomyCategory)

        expected_categories = [
            "prompt_injection", "jailbreak", "system_prompt_leak",
            "adversarial_evasion", "model_extraction", "data_poisoning",
            "agent_attacks", "supply_chain", "multimodal", "combination_attacks"
        ]

        category_values = [c.value for c in categories]
        for expected in expected_categories:
            assert expected in category_values, f"Missing category: {expected}"


class TestRobustPayloads:
    """Tests for robust payload generation (WS-1)"""

    def test_robust_payloads_generated(self):
        """Verify robust payloads are generated"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        # Flatten all test cases
        all_cases = []
        for cases in output.categories.values():
            all_cases.extend(cases)

        # Find robust payloads by complexity
        robust_payloads = [
            tc for tc in all_cases
            if tc.complexity_level >= 3
        ]

        assert len(robust_payloads) >= 5, f"Expected at least 5 robust payloads, got {len(robust_payloads)}"

    def test_robust_payloads_length(self):
        """Verify robust payloads are 100+ characters"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_cases = []
        for cases in output.categories.values():
            all_cases.extend(cases)

        robust_payloads = [tc for tc in all_cases if tc.complexity_level >= 4]

        for tc in robust_payloads:
            assert len(tc.payload) >= 100, f"Robust payload '{tc.name}' is only {len(tc.payload)} chars"

    def test_complexity_level_field_exists(self):
        """Verify complexity_level field is populated"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_cases = []
        for cases in output.categories.values():
            all_cases.extend(cases)

        for tc in all_cases:
            assert hasattr(tc, 'complexity_level')
            assert 1 <= tc.complexity_level <= 5


class TestCombinationAttacks:
    """Tests for combination attack chains (WS-2)"""

    def test_combination_attacks_generated(self):
        """Verify combination attacks are in corpus"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        combo_key = TaxonomyCategory.COMBINATION_ATTACKS.value
        combo_attacks = output.categories.get(combo_key, [])

        assert len(combo_attacks) >= 5, f"Expected 5+ combination attacks, got {len(combo_attacks)}"

    def test_combination_chain_metadata(self):
        """Verify combination chains have technique list"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        combo_key = TaxonomyCategory.COMBINATION_ATTACKS.value
        combo_attacks = output.categories.get(combo_key, [])

        for tc in combo_attacks:
            assert hasattr(tc, 'techniques_used')
            assert len(tc.techniques_used) >= 2, f"Combo '{tc.name}' should combine 2+ techniques"

    def test_combination_chain_sequence(self):
        """Verify combination chains have sequence order"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        combo_key = TaxonomyCategory.COMBINATION_ATTACKS.value
        combo_attacks = output.categories.get(combo_key, [])

        for tc in combo_attacks:
            assert hasattr(tc, 'chain_sequence')
            assert isinstance(tc.chain_sequence, list)


class TestJailbreakResearch:
    """Tests for 2024-2026 jailbreak research integration (WS-3)"""

    def test_jailbreak_coverage(self):
        """Verify all research categories present"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        jailbreak_key = TaxonomyCategory.JAILBREAK.value
        jailbreaks = output.categories.get(jailbreak_key, [])

        # Should have at least 15 jailbreak payloads
        assert len(jailbreaks) >= 15, f"Expected 15+ jailbreaks, got {len(jailbreaks)}"

    def test_research_techniques_covered(self):
        """Verify 2024-2026 research techniques are included"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        jailbreak_key = TaxonomyCategory.JAILBREAK.value
        jailbreaks = output.categories.get(jailbreak_key, [])

        # Check for key research techniques
        research_keywords = [
            "many_shot", "crescendo", "skeleton", "gcg", "tap", "pair",
            "best_of_n", "deep_inception", "renellm", "autodan"
        ]

        jailbreak_names = [tc.name.lower() for tc in jailbreaks]
        found_techniques = []

        for keyword in research_keywords:
            for name in jailbreak_names:
                if keyword in name:
                    found_techniques.append(keyword)
                    break

        assert len(found_techniques) >= 3, f"Expected 3+ research techniques, found: {found_techniques}"

    def test_research_source_metadata(self):
        """Verify research payloads have source attribution"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_cases = []
        for cases in output.categories.values():
            all_cases.extend(cases)

        # Find payloads with research_source
        research_attributed = [
            tc for tc in all_cases
            if tc.research_source is not None
        ]

        assert len(research_attributed) >= 3, "Expected 3+ payloads with research attribution"

    def test_model_specific_attacks(self):
        """Verify model-specific attack variants exist"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_cases = []
        for cases in output.categories.values():
            all_cases.extend(cases)

        # Find payloads with target_models
        model_specific = [
            tc for tc in all_cases
            if len(tc.target_models) > 0
        ]

        assert len(model_specific) >= 2, "Expected 2+ model-specific payloads"


class TestCorpusOutput:
    """Tests for corpus export and output"""

    def test_corpus_total_count(self):
        """Verify 100+ test cases generated"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        total = output.total_count()
        # Should have at least 100 test cases
        assert total >= 100, f"Expected 100+ test cases, got {total}"

    def test_corpus_output_structure(self):
        """Verify CorpusOutput has correct structure"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        assert hasattr(output, 'metadata')
        assert hasattr(output, 'categories')
        assert hasattr(output, 'statistics')
        assert isinstance(output.categories, dict)

    def test_unique_ids(self):
        """Verify all test case IDs are unique"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_ids = []
        for cases in output.categories.values():
            for tc in cases:
                all_ids.append(tc.id)

        assert len(all_ids) == len(set(all_ids)), "Duplicate test case IDs found"


class TestBackwardCompatibility:
    """Tests ensuring backward compatibility"""

    def test_existing_categories_preserved(self):
        """Verify original categories still work"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        original_categories = [
            TaxonomyCategory.PROMPT_INJECTION,
            TaxonomyCategory.JAILBREAK,
            TaxonomyCategory.ADVERSARIAL_EVASION,
            TaxonomyCategory.DATA_POISONING,
            TaxonomyCategory.SUPPLY_CHAIN,
            TaxonomyCategory.AGENT_ATTACKS,
        ]

        for cat in original_categories:
            cat_cases = output.categories.get(cat.value, [])
            assert len(cat_cases) >= 3, f"Category {cat.value} should have 3+ cases"

    def test_test_case_dataclass_fields(self):
        """Verify TestCase has all expected fields"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        # Get first test case
        first_cat = list(output.categories.keys())[0]
        tc = output.categories[first_cat][0]

        # Original required fields
        required_original = ["id", "name", "description", "category", "payload", "expected_behavior"]
        for field in required_original:
            assert hasattr(tc, field), f"Missing original field: {field}"

        # New optional fields
        new_fields = ["complexity_level", "techniques_used", "chain_sequence", "target_models"]
        for field in new_fields:
            assert hasattr(tc, field), f"Missing new field: {field}"


class TestPayloadQuality:
    """Tests for payload quality and content"""

    def test_no_duplicate_payloads(self):
        """Verify no exact duplicate payloads exist"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_payloads = []
        for cases in output.categories.values():
            for tc in cases:
                all_payloads.append(tc.payload)

        unique_payloads = set(all_payloads)

        # Allow small number of duplicates (some may be intentional variants)
        dup_count = len(all_payloads) - len(unique_payloads)
        assert dup_count < 5, f"Found {dup_count} duplicate payloads"

    def test_payloads_are_non_empty(self):
        """Verify all payloads have content"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        for cases in output.categories.values():
            for tc in cases:
                assert len(tc.payload.strip()) > 0, f"Empty payload in {tc.name}"

    def test_severity_distribution(self):
        """Verify mix of severity levels"""
        generator = TestCorpusGenerator()
        output = generator.generate_all()

        all_severities = []
        for cases in output.categories.values():
            for tc in cases:
                all_severities.append(tc.severity.value)

        unique_severities = set(all_severities)

        # Should have at least 3 different severity levels
        assert len(unique_severities) >= 3, "Expected variety in severity levels"


class TestTargetInterpolation:
    """Tests for target-based payload interpolation"""

    def test_init_with_target(self):
        """Test initialization with target parameter"""
        generator = TestCorpusGenerator(target="AcmeCorp Data")
        assert generator.target == "AcmeCorp Data"

    def test_init_without_target(self):
        """Test initialization without target (default)"""
        generator = TestCorpusGenerator()
        assert generator.target is None

    def test_init_with_empty_string_target(self):
        """Test empty string target is treated as None"""
        generator = TestCorpusGenerator(target="")
        assert generator.target is None

    def test_interpolate_target_method(self):
        """Test _interpolate_target helper method"""
        generator = TestCorpusGenerator(target="User ID 02")
        result = generator._interpolate_target("Extract {TARGET} data")
        assert result == "Extract User ID 02 data"

    def test_interpolate_target_no_placeholder(self):
        """Test interpolation when no placeholder exists"""
        generator = TestCorpusGenerator(target="User ID 02")
        result = generator._interpolate_target("No placeholder here")
        assert result == "No placeholder here"

    def test_interpolate_target_when_none(self):
        """Test interpolation returns unchanged when target is None"""
        generator = TestCorpusGenerator(target=None)
        result = generator._interpolate_target("Extract {TARGET} data")
        assert result == "Extract {TARGET} data"

    def test_target_payloads_generated(self):
        """Verify target-specific payloads are generated"""
        target = "Admin Credentials"
        generator = TestCorpusGenerator(target=target)
        output = generator.generate_all()

        all_payloads = []
        for cases in output.categories.values():
            for tc in cases:
                all_payloads.append(tc.payload)

        # At least some payloads should contain the target
        target_in_payloads = [p for p in all_payloads if target in p]
        assert len(target_in_payloads) >= 5, f"Expected 5+ payloads with target, got {len(target_in_payloads)}"

    def test_no_target_no_target_payloads(self):
        """Verify no target-specific payloads when target is None"""
        generator = TestCorpusGenerator(target=None)
        output = generator.generate_all()

        all_payloads = []
        for cases in output.categories.values():
            for tc in cases:
                all_payloads.append(tc.payload)

        # No payloads should contain literal {TARGET}
        target_placeholders = [p for p in all_payloads if "{TARGET}" in p]
        assert len(target_placeholders) == 0, "Found unexpected {TARGET} placeholders"

    def test_target_with_special_characters(self):
        """Test target with special characters"""
        target = "User <admin> & 'root'"
        generator = TestCorpusGenerator(target=target)
        output = generator.generate_all()

        # Should not crash and should generate payloads
        total = sum(len(cases) for cases in output.categories.values())
        assert total > 0, "Should generate test cases with special character target"
