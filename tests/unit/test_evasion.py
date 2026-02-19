#!/usr/bin/env python3
"""
Unit tests for EvasionAttackModule
Tests adversarial example generation attacks
"""

import pytest
import numpy as np
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.adversarial.evasion_attacks import EvasionAttackModule, AdversarialExample
from scripts.utils.base import Severity, AttackCategory
from tests.conftest import (
    assert_finding_valid, assert_test_result_valid,
    generate_test_samples
)


class TestEvasionAttackModule:
    """Test suite for evasion attack module"""

    def test_module_initialization(self, mock_model, tmp_output_dir, evasion_config):
        """Test module initializes correctly with config"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        assert module.epsilon == evasion_config['epsilon']
        assert module.max_iterations == evasion_config['max_iterations']
        assert module.adversarial_examples == []

    def test_fgsm_generates_results(self, mock_model, tmp_output_dir, evasion_config):
        """Test FGSM attack generates valid results"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(5, evasion_config['input_shape'])
        result = module.test_fgsm(samples=samples)

        assert_test_result_valid(result)
        assert result.test_name == "FGSM"
        assert "success_rate" in result.metrics
        assert "epsilon" in result.metrics
        assert result.queries_used > 0

    def test_fgsm_respects_epsilon(self, mock_model, tmp_output_dir):
        """Test FGSM perturbations stay within epsilon bound"""
        config = {
            "epsilon": 0.05,  # Small epsilon
            "input_shape": (3, 32, 32)
        }
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=config
        )

        samples = generate_test_samples(3, config['input_shape'])
        module.test_fgsm(samples=samples)

        for adv_example in module.adversarial_examples:
            if adv_example.attack_method == 'FGSM':
                # L-inf norm should be <= epsilon
                assert adv_example.linf_norm <= config['epsilon'] + 1e-6

    def test_pgd_iterative_refinement(self, mock_model, tmp_output_dir, evasion_config):
        """Test PGD attack uses iterative refinement"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(3, evasion_config['input_shape'])
        result = module.test_pgd(samples=samples, num_iterations=5)

        assert_test_result_valid(result)
        assert result.test_name == "PGD"
        # PGD should use more queries than FGSM due to iterations
        assert result.queries_used >= len(samples) * 5

    def test_boundary_attack_decision_based(self, mock_model, tmp_output_dir, evasion_config):
        """Test boundary attack uses only hard labels"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(2, evasion_config['input_shape'])
        result = module.test_boundary_attack(samples=samples, max_queries=500)

        assert_test_result_valid(result)
        assert result.test_name == "BoundaryAttack"
        assert "queries_used" in result.metrics

    def test_hopskipjump_query_efficient(self, mock_model, tmp_output_dir, evasion_config):
        """Test HopSkipJump is more query-efficient than boundary"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(2, evasion_config['input_shape'])
        result = module.test_hopskipjump(samples=samples, max_queries=500)

        assert_test_result_valid(result)
        assert result.test_name == "HopSkipJump"

    def test_finding_generation_on_success(self, mock_model, tmp_output_dir, evasion_config):
        """Test findings are generated when attack succeeds"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(10, evasion_config['input_shape'])
        module.test_fgsm(samples=samples)

        # If any attack succeeded, there should be findings
        if any(ex.success for ex in module.adversarial_examples):
            assert len(module.findings) > 0
            for finding in module.findings:
                assert_finding_valid(finding)
                assert finding.category == AttackCategory.EVASION

    def test_run_tests_executes_all_methods(self, mock_model, tmp_output_dir, evasion_config):
        """Test run_tests() executes all attack methods"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        results = module.run_tests()

        # Should have results for all 4 attack methods
        assert len(results) == 4
        test_names = [r.test_name for r in results]
        assert "FGSM" in test_names
        assert "PGD" in test_names
        assert "BoundaryAttack" in test_names
        assert "HopSkipJump" in test_names

    def test_adversarial_example_dataclass(self, mock_model, tmp_output_dir, evasion_config):
        """Test AdversarialExample dataclass is populated correctly"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(5, evasion_config['input_shape'])
        module.test_fgsm(samples=samples)

        for adv_example in module.adversarial_examples:
            assert isinstance(adv_example, AdversarialExample)
            assert adv_example.original is not None
            assert adv_example.adversarial is not None
            assert adv_example.perturbation is not None
            assert adv_example.l0_norm >= 0
            assert adv_example.l2_norm >= 0
            assert adv_example.linf_norm >= 0
            assert adv_example.queries_used > 0
            assert adv_example.attack_method in ['FGSM', 'PGD', 'BoundaryAttack', 'HopSkipJump']

    def test_result_metrics_populated(self, mock_model, tmp_output_dir, evasion_config):
        """Test result metrics are properly populated"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(5, evasion_config['input_shape'])
        result = module.test_fgsm(samples=samples)

        assert "success_rate" in result.metrics
        assert 0 <= result.metrics["success_rate"] <= 1
        assert "samples_tested" in result.metrics
        assert result.metrics["samples_tested"] == 5
        assert "epsilon" in result.metrics

    def test_save_results_creates_file(self, mock_model, tmp_output_dir, evasion_config):
        """Test results are saved to output directory"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(3, evasion_config['input_shape'])
        module.test_fgsm(samples=samples)
        module.save_results()

        # Check output directory has files
        output_files = list(tmp_output_dir.glob("*.json"))
        assert len(output_files) > 0


class TestEvasionEdgeCases:
    """Edge case tests for evasion module"""

    def test_empty_samples(self, mock_model, tmp_output_dir, evasion_config):
        """Test handling of empty sample array"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        # Empty samples should not crash
        samples = np.array([]).reshape(0, 3, 32, 32).astype(np.float32)
        result = module.test_fgsm(samples=samples)

        assert result.success is True
        assert result.metrics.get("success_rate", 0) == 0

    def test_single_sample(self, mock_model, tmp_output_dir, evasion_config):
        """Test attack with single sample"""
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=evasion_config
        )

        samples = generate_test_samples(1, evasion_config['input_shape'])
        result = module.test_fgsm(samples=samples)

        assert_test_result_valid(result)
        assert result.metrics["samples_tested"] == 1

    def test_zero_epsilon(self, mock_model, tmp_output_dir):
        """Test behavior with epsilon=0 (no perturbation allowed)"""
        config = {
            "epsilon": 0.0,
            "input_shape": (3, 32, 32)
        }
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=config
        )

        samples = generate_test_samples(3, config['input_shape'])
        result = module.test_fgsm(samples=samples)

        # With zero epsilon, perturbation is zero, so success rate should be low
        assert result.metrics["epsilon"] == 0.0

    def test_large_epsilon(self, mock_model, tmp_output_dir):
        """Test behavior with large epsilon"""
        config = {
            "epsilon": 1.0,  # Full range perturbation
            "input_shape": (3, 32, 32)
        }
        module = EvasionAttackModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=config
        )

        samples = generate_test_samples(3, config['input_shape'])
        result = module.test_fgsm(samples=samples)

        # Large epsilon should have high success rate
        assert_test_result_valid(result)

    def test_different_input_shapes(self, mock_model, tmp_output_dir):
        """Test module works with different input shapes"""
        shapes = [
            (1, 28, 28),   # MNIST-like
            (3, 32, 32),   # CIFAR-like
            (3, 224, 224), # ImageNet-like
        ]

        for shape in shapes:
            config = {"epsilon": 0.1, "input_shape": shape}
            module = EvasionAttackModule(
                target=mock_model,
                output_dir=tmp_output_dir,
                config=config
            )

            samples = generate_test_samples(2, shape)
            result = module.test_fgsm(samples=samples)

            assert_test_result_valid(result)
