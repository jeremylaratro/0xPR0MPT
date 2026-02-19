#!/usr/bin/env python3
"""
Unit tests for ModelExtractionModule
Tests model stealing/extraction attacks
"""

import pytest
import numpy as np
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.model_extraction.extractor import ModelExtractionModule, ExtractionResult
from scripts.utils.base import Severity, AttackCategory
from tests.conftest import assert_finding_valid, assert_test_result_valid


class TestModelExtractionModule:
    """Test suite for model extraction module"""

    def test_module_initialization(self, mock_model, tmp_output_dir, extraction_config):
        """Test module initializes correctly with config"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        assert module.query_budget == extraction_config['query_budget']
        assert module.num_classes == extraction_config['num_classes']
        assert module.extraction_results == []

    def test_random_query_extraction(self, mock_model, tmp_output_dir, extraction_config):
        """Test random query extraction generates results"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        result = module.test_random_query_extraction(num_queries=50)

        assert_test_result_valid(result)
        assert result.test_name == "RandomQuery"
        assert "agreement_rate" in result.metrics
        assert "queries_used" in result.metrics
        assert result.queries_used <= extraction_config['query_budget']

    def test_jacobian_augmentation(self, mock_model, tmp_output_dir, extraction_config):
        """Test Jacobian-based augmentation extraction"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        result = module.test_jacobian_extraction(
            num_initial=20,
            augmentation_rounds=2
        )

        assert_test_result_valid(result)
        assert result.test_name == "JacobianAugmentation"
        assert "augmentation_rounds" in result.metrics
        assert result.metrics["augmentation_rounds"] == 2

    def test_active_learning_selection(self, mock_model, tmp_output_dir, extraction_config):
        """Test active learning based extraction"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        result = module.test_active_learning_extraction(
            initial_samples=20,
            iterations=3
        )

        assert_test_result_valid(result)
        assert result.test_name == "ActiveLearning"
        assert "efficiency" in result.metrics

    def test_knockoff_extraction(self, mock_model, tmp_output_dir, extraction_config):
        """Test knockoff networks extraction"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        result = module.test_knockoff_extraction()

        assert_test_result_valid(result)
        assert result.test_name == "KnockoffNets"
        assert "label_coverage" in result.metrics

    def test_query_budget_respected(self, mock_model, tmp_output_dir):
        """Test extraction stays within query budget"""
        small_budget = 50
        config = {
            'query_budget': small_budget,
            'num_classes': 10,
            'input_shape': (3, 32, 32)
        }

        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=config
        )

        result = module.test_random_query_extraction()

        assert result.queries_used <= small_budget

    def test_agreement_rate_calculation(self, mock_model, tmp_output_dir, extraction_config):
        """Test agreement rate is calculated correctly"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        result = module.test_random_query_extraction(num_queries=100)

        agreement_rate = result.metrics.get("agreement_rate", 0)
        assert 0 <= agreement_rate <= 1

    def test_extraction_result_dataclass(self, mock_model, tmp_output_dir, extraction_config):
        """Test ExtractionResult dataclass is populated"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        module.test_random_query_extraction(num_queries=50)

        assert len(module.extraction_results) > 0
        for ext_result in module.extraction_results:
            assert isinstance(ext_result, ExtractionResult)
            assert ext_result.queries_used > 0
            assert 0 <= ext_result.agreement_rate <= 1
            assert ext_result.extraction_method in [
                "RandomQuery", "JacobianAugmentation",
                "ActiveLearning", "KnockoffNets"
            ]

    def test_finding_generation_high_agreement(self, mock_model, tmp_output_dir, extraction_config):
        """Test findings are generated when agreement rate is high"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        # Run all tests to maximize chance of generating findings
        module.run_tests()

        for finding in module.findings:
            assert_finding_valid(finding)
            assert finding.category == AttackCategory.EXTRACTION

    def test_run_tests_executes_all_methods(self, mock_model, tmp_output_dir, extraction_config):
        """Test run_tests() executes all extraction methods"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        results = module.run_tests()

        assert len(results) == 4
        test_names = [r.test_name for r in results]
        assert "RandomQuery" in test_names
        assert "JacobianAugmentation" in test_names
        assert "ActiveLearning" in test_names
        assert "KnockoffNets" in test_names

    def test_query_log_populated(self, mock_model, tmp_output_dir, extraction_config):
        """Test query log tracks all queries"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        module.test_random_query_extraction(num_queries=10)

        assert len(module.query_log) > 0
        for entry in module.query_log:
            assert "query_hash" in entry
            assert "response" in entry
            assert "method" in entry


class TestExtractionHelpers:
    """Test helper methods in extraction module"""

    def test_generate_random_queries(self, mock_model, tmp_output_dir, extraction_config):
        """Test random query generation"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        queries = module._generate_random_queries(20)

        assert queries.shape == (20, *extraction_config['input_shape'])
        assert queries.dtype == np.float32
        assert queries.min() >= 0
        assert queries.max() <= 1

    def test_get_predicted_class(self, mock_model, tmp_output_dir, extraction_config):
        """Test class extraction from predictions"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        # Test dict with 'class' key
        assert module._get_predicted_class({"class": 5}) == 5

        # Test dict with 'prediction' key
        assert module._get_predicted_class({"prediction": 3}) == 3

        # Test dict with 'probabilities'
        probs = [0.1, 0.2, 0.7]
        assert module._get_predicted_class({"probabilities": probs}) == 2

        # Test list (argmax)
        assert module._get_predicted_class([0.1, 0.9, 0.0]) == 1

        # Test numpy array
        assert module._get_predicted_class(np.array([0.1, 0.1, 0.8])) == 2

        # Test scalar
        assert module._get_predicted_class(7) == 7

    def test_jacobian_augment(self, mock_model, tmp_output_dir, extraction_config):
        """Test Jacobian augmentation generates samples"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        sample = np.random.rand(*extraction_config['input_shape']).astype(np.float32)
        augmented = module._jacobian_augment(sample, [0, 1, 2], num_augmented=5)

        assert len(augmented) == 5
        for aug in augmented:
            assert aug.shape == sample.shape

    def test_estimate_uncertainty(self, mock_model, tmp_output_dir, extraction_config):
        """Test uncertainty estimation for active learning"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        shape = extraction_config['input_shape']
        candidate = np.random.rand(*shape).astype(np.float32)
        known_queries = [np.random.rand(*shape) for _ in range(10)]
        known_labels = list(range(10))

        uncertainty = module._estimate_uncertainty(candidate, known_queries, known_labels)

        assert uncertainty >= 0

    def test_calculate_entropy(self, mock_model, tmp_output_dir, extraction_config):
        """Test entropy calculation for soft labels"""
        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=extraction_config
        )

        # Uniform distribution - high entropy
        uniform = [[0.1] * 10 for _ in range(5)]
        entropy_uniform = module._calculate_entropy(uniform)

        # Peaked distribution - low entropy
        peaked = [[0.9] + [0.01] * 9 for _ in range(5)]
        entropy_peaked = module._calculate_entropy(peaked)

        assert entropy_uniform > entropy_peaked

        # Empty list
        assert module._calculate_entropy([]) == 0


class TestExtractionEdgeCases:
    """Edge case tests for extraction module"""

    def test_single_class_model(self, tmp_output_dir):
        """Test extraction with single class model"""
        from tests.conftest import MockModelInterface

        single_class_model = MockModelInterface(num_classes=1)
        config = {
            'query_budget': 50,
            'num_classes': 1,
            'input_shape': (3, 32, 32)
        }

        module = ModelExtractionModule(
            target=single_class_model,
            output_dir=tmp_output_dir,
            config=config
        )

        result = module.test_random_query_extraction(num_queries=20)
        assert_test_result_valid(result)

    def test_many_classes(self, tmp_output_dir):
        """Test extraction with many classes"""
        from tests.conftest import MockModelInterface

        many_class_model = MockModelInterface(num_classes=1000)
        config = {
            'query_budget': 100,
            'num_classes': 1000,
            'input_shape': (3, 32, 32)
        }

        module = ModelExtractionModule(
            target=many_class_model,
            output_dir=tmp_output_dir,
            config=config
        )

        result = module.test_random_query_extraction(num_queries=50)
        assert_test_result_valid(result)
        # Label coverage should be low with only 50 queries for 1000 classes
        assert result.metrics["label_coverage"] < 0.1

    def test_zero_query_budget(self, mock_model, tmp_output_dir):
        """Test behavior with zero query budget"""
        config = {
            'query_budget': 0,
            'num_classes': 10,
            'input_shape': (3, 32, 32)
        }

        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=config
        )

        result = module.test_random_query_extraction()

        # Should handle gracefully
        assert_test_result_valid(result)
        assert result.queries_used == 0

    def test_tiny_input_shape(self, mock_model, tmp_output_dir):
        """Test with very small input shape"""
        config = {
            'query_budget': 50,
            'num_classes': 10,
            'input_shape': (1, 2, 2)
        }

        module = ModelExtractionModule(
            target=mock_model,
            output_dir=tmp_output_dir,
            config=config
        )

        result = module.test_random_query_extraction(num_queries=20)
        assert_test_result_valid(result)
