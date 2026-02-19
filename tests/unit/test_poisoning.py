#!/usr/bin/env python3
"""
Unit tests for DataPoisoningModule
Tests data poisoning assessment functionality
"""

import pytest
import numpy as np
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.data_poisoning.poisoning_tests import DataPoisoningModule
from scripts.utils.base import Severity, AttackCategory
from tests.conftest import assert_finding_valid, assert_test_result_valid


class TestDataPoisoningModule:
    """Test suite for data poisoning module"""

    @pytest.fixture
    def poisoning_config(self):
        return {
            "num_classes": 10,
            "trigger_size": 5,
            "trigger_position": "bottom_right",
            "input_shape": (3, 32, 32)
        }

    def test_module_initialization(self, mock_model, tmp_output_dir, poisoning_config):
        """Test module initializes correctly"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        assert module is not None

    def test_label_flip_assessment(self, mock_model, tmp_output_dir, poisoning_config):
        """Test label flip vulnerability assessment"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        result = module.assess_label_flip()

        assert_test_result_valid(result)
        assert result.test_name == "LabelFlipAssessment"

    def test_backdoor_feasibility(self, mock_model, tmp_output_dir, poisoning_config):
        """Test backdoor/trojan feasibility assessment"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        result = module.assess_backdoor()

        assert_test_result_valid(result)
        assert result.test_name == "BackdoorAssessment"

    def test_clean_label_attack(self, mock_model, tmp_output_dir, poisoning_config):
        """Test clean-label attack potential"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        result = module.assess_clean_label()

        assert_test_result_valid(result)
        assert result.test_name == "CleanLabelAssessment"

    def test_trigger_pattern_detection(self, mock_model, tmp_output_dir, poisoning_config):
        """Test trigger pattern detection"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        result = module.test_trigger_detection()

        assert_test_result_valid(result)

    def test_poison_rate_estimation(self, mock_model, tmp_output_dir, poisoning_config):
        """Test poison rate estimation"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        result = module.estimate_poison_rate()

        assert_test_result_valid(result)
        if "estimated_rates" in result.metrics:
            rates = result.metrics["estimated_rates"]
            for rate in rates.values():
                assert 0 <= rate <= 1

    def test_run_tests_executes_all(self, mock_model, tmp_output_dir, poisoning_config):
        """Test run_tests() executes all methods"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        results = module.run_tests()

        assert len(results) >= 3  # At least label flip, backdoor, clean-label
        for result in results:
            assert_test_result_valid(result)

    def test_finding_generation(self, mock_model, tmp_output_dir, poisoning_config):
        """Test findings are generated appropriately"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        module.run_tests()

        for finding in module.findings:
            assert_finding_valid(finding)
            assert finding.category == AttackCategory.DATA_POISONING


class TestPoisoningHelpers:
    """Test helper methods"""

    @pytest.fixture
    def poisoning_config(self):
        return {
            "num_classes": 10,
            "trigger_size": 5,
            "trigger_position": "bottom_right",
            "input_shape": (3, 32, 32)
        }

    def test_create_trigger_pattern(self, mock_model, tmp_output_dir, poisoning_config):
        """Test trigger pattern generation"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        trigger = module._create_trigger_pattern()

        # Trigger should match input_shape
        assert trigger.shape == tuple(poisoning_config["input_shape"])

    def test_apply_trigger(self, mock_model, tmp_output_dir, poisoning_config):
        """Test trigger application to samples"""
        module = DataPoisoningModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=poisoning_config
        )

        # Create batch of samples
        samples = np.random.rand(5, *poisoning_config["input_shape"]).astype(np.float32)
        trigger = module._create_trigger_pattern()
        poisoned = module._apply_trigger(samples, trigger)

        assert poisoned.shape == samples.shape
        # Poisoned samples should differ from originals where trigger is applied
        mask = trigger > 0
        for i in range(len(samples)):
            assert not np.allclose(samples[i][mask], poisoned[i][mask])
