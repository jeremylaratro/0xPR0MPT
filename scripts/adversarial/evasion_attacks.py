#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Adversarial Evasion Attacks
Implements white-box and black-box adversarial example generation
"""

import time
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.base import (
    TestModule, ModelInterface, TestResult, Finding,
    Severity, AttackCategory
)


@dataclass
class AdversarialExample:
    """Container for adversarial example data"""
    original: np.ndarray
    adversarial: np.ndarray
    perturbation: np.ndarray
    original_prediction: Any
    adversarial_prediction: Any
    l0_norm: float
    l2_norm: float
    linf_norm: float
    queries_used: int
    attack_method: str
    success: bool


class EvasionAttackModule(TestModule):
    """
    Adversarial evasion attack testing module
    Tests model robustness against adversarial perturbations
    """

    def __init__(
        self,
        target: ModelInterface,
        output_dir: Path,
        config: Optional[Dict] = None
    ):
        super().__init__(target, output_dir, config)

        # Default configuration
        self.epsilon = config.get('epsilon', 0.3)
        self.epsilon_step = config.get('epsilon_step', 0.01)
        self.max_iterations = config.get('max_iterations', 100)
        self.targeted = config.get('targeted', False)
        self.target_class = config.get('target_class', None)

        self.adversarial_examples: List[AdversarialExample] = []

    def run_tests(self) -> List[TestResult]:
        """Execute all evasion attack tests"""
        results = []

        # Run available attack methods based on access level
        test_methods = [
            ('FGSM', self.test_fgsm),
            ('PGD', self.test_pgd),
            ('BoundaryAttack', self.test_boundary_attack),
            ('HopSkipJump', self.test_hopskipjump),
        ]

        for name, method in test_methods:
            self.logger.info(f"Running {name} attack test...")
            try:
                result = method()
                results.append(result)
                self.results.append(result)
            except Exception as e:
                self.logger.error(f"{name} test failed: {e}")
                results.append(TestResult(
                    test_name=name,
                    success=False,
                    attack_succeeded=False,
                    metrics={},
                    duration_seconds=0,
                    error=str(e)
                ))

        self.save_results()
        return results

    def test_fgsm(self, samples: Optional[np.ndarray] = None) -> TestResult:
        """
        Fast Gradient Sign Method (FGSM)
        White-box attack requiring gradient access
        """
        start_time = time.time()

        if samples is None:
            samples = self._generate_test_samples()

        success_count = 0
        total_queries = 0
        perturbation_norms = []

        for sample in samples:
            try:
                # Get original prediction
                orig_pred = self.target.predict(sample.tolist())
                orig_class = self._get_predicted_class(orig_pred)

                # FGSM requires gradient - simulate with finite differences
                # In real scenario, this would use actual gradients
                gradient = self._estimate_gradient(sample, orig_class)

                # Generate perturbation
                perturbation = self.epsilon * np.sign(gradient)
                adversarial = np.clip(sample + perturbation, 0, 1)

                # Test adversarial example
                adv_pred = self.target.predict(adversarial.tolist())
                adv_class = self._get_predicted_class(adv_pred)
                total_queries += 2

                if adv_class != orig_class:
                    success_count += 1
                    perturbation_norms.append(np.linalg.norm(perturbation))

                    self.adversarial_examples.append(AdversarialExample(
                        original=sample,
                        adversarial=adversarial,
                        perturbation=perturbation,
                        original_prediction=orig_class,
                        adversarial_prediction=adv_class,
                        l0_norm=np.count_nonzero(perturbation),
                        l2_norm=np.linalg.norm(perturbation),
                        linf_norm=np.max(np.abs(perturbation)),
                        queries_used=2,
                        attack_method='FGSM',
                        success=True
                    ))

            except Exception as e:
                self.logger.debug(f"FGSM sample failed: {e}")

        duration = time.time() - start_time
        success_rate = success_count / len(samples) if samples.size > 0 else 0

        if success_rate > 0.5:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Vulnerable to FGSM Adversarial Attack",
                category=AttackCategory.EVASION,
                severity=Severity.HIGH,
                description=f"The model is vulnerable to Fast Gradient Sign Method attacks with {success_rate*100:.1f}% success rate at epsilon={self.epsilon}",
                evidence={
                    "success_rate": success_rate,
                    "epsilon": self.epsilon,
                    "samples_tested": len(samples),
                    "avg_perturbation_norm": np.mean(perturbation_norms) if perturbation_norms else 0
                },
                remediation="Implement adversarial training with FGSM examples. Consider input preprocessing or certified defenses."
            ))

        return TestResult(
            test_name="FGSM",
            success=True,
            attack_succeeded=success_rate > 0.1,
            metrics={
                "success_rate": success_rate,
                "epsilon": self.epsilon,
                "samples_tested": len(samples),
                "avg_perturbation_l2": np.mean(perturbation_norms) if perturbation_norms else 0
            },
            duration_seconds=duration,
            queries_used=total_queries
        )

    def test_pgd(
        self,
        samples: Optional[np.ndarray] = None,
        num_iterations: int = 40,
        step_size: Optional[float] = None
    ) -> TestResult:
        """
        Projected Gradient Descent (PGD)
        Stronger iterative white-box attack
        """
        start_time = time.time()

        if samples is None:
            samples = self._generate_test_samples()

        if step_size is None:
            step_size = self.epsilon / 4

        success_count = 0
        total_queries = 0
        perturbation_norms = []

        for sample in samples:
            try:
                orig_pred = self.target.predict(sample.tolist())
                orig_class = self._get_predicted_class(orig_pred)

                # Initialize with random perturbation within epsilon ball
                perturbation = np.random.uniform(-self.epsilon, self.epsilon, sample.shape)
                adversarial = np.clip(sample + perturbation, 0, 1)

                for _ in range(num_iterations):
                    # Estimate gradient
                    gradient = self._estimate_gradient(adversarial, orig_class)
                    total_queries += 1

                    # Update perturbation
                    perturbation = perturbation + step_size * np.sign(gradient)

                    # Project back to epsilon ball
                    perturbation = np.clip(perturbation, -self.epsilon, self.epsilon)
                    adversarial = np.clip(sample + perturbation, 0, 1)

                # Final check
                adv_pred = self.target.predict(adversarial.tolist())
                adv_class = self._get_predicted_class(adv_pred)
                total_queries += 1

                if adv_class != orig_class:
                    success_count += 1
                    perturbation_norms.append(np.linalg.norm(perturbation))

                    self.adversarial_examples.append(AdversarialExample(
                        original=sample,
                        adversarial=adversarial,
                        perturbation=perturbation,
                        original_prediction=orig_class,
                        adversarial_prediction=adv_class,
                        l0_norm=np.count_nonzero(perturbation),
                        l2_norm=np.linalg.norm(perturbation),
                        linf_norm=np.max(np.abs(perturbation)),
                        queries_used=num_iterations + 1,
                        attack_method='PGD',
                        success=True
                    ))

            except Exception as e:
                self.logger.debug(f"PGD sample failed: {e}")

        duration = time.time() - start_time
        success_rate = success_count / len(samples) if samples.size > 0 else 0

        if success_rate > 0.3:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Vulnerable to PGD Adversarial Attack",
                category=AttackCategory.EVASION,
                severity=Severity.CRITICAL,
                description=f"The model is vulnerable to Projected Gradient Descent attacks with {success_rate*100:.1f}% success rate. PGD is considered a strong attack; vulnerability indicates insufficient robustness.",
                evidence={
                    "success_rate": success_rate,
                    "epsilon": self.epsilon,
                    "iterations": num_iterations,
                    "step_size": step_size,
                    "samples_tested": len(samples)
                },
                remediation="Implement PGD-based adversarial training. Consider certified defense methods like randomized smoothing.",
                cvss_score=8.5
            ))

        return TestResult(
            test_name="PGD",
            success=True,
            attack_succeeded=success_rate > 0.1,
            metrics={
                "success_rate": success_rate,
                "epsilon": self.epsilon,
                "iterations": num_iterations,
                "samples_tested": len(samples),
                "avg_perturbation_l2": np.mean(perturbation_norms) if perturbation_norms else 0
            },
            duration_seconds=duration,
            queries_used=total_queries
        )

    def test_boundary_attack(
        self,
        samples: Optional[np.ndarray] = None,
        max_queries: int = 10000
    ) -> TestResult:
        """
        Boundary Attack (Decision-Based)
        Black-box attack requiring only final decisions
        """
        start_time = time.time()

        if samples is None:
            samples = self._generate_test_samples()

        success_count = 0
        total_queries = 0
        perturbation_norms = []

        for sample in samples:
            try:
                orig_pred = self.target.predict(sample.tolist())
                orig_class = self._get_predicted_class(orig_pred)
                total_queries += 1

                # Initialize from adversarial starting point
                # (random image that gets different prediction)
                adversarial = self._find_initial_adversarial(sample, orig_class)
                if adversarial is None:
                    continue
                total_queries += 100  # approximate queries for initialization

                # Binary search to get closer to boundary
                for _ in range(100):
                    if total_queries >= max_queries:
                        break

                    # Move toward original
                    midpoint = (sample + adversarial) / 2
                    mid_pred = self.target.predict(midpoint.tolist())
                    mid_class = self._get_predicted_class(mid_pred)
                    total_queries += 1

                    if mid_class != orig_class:
                        adversarial = midpoint
                    else:
                        break

                # Random walk along boundary
                step_size = 0.01
                for _ in range(min(1000, max_queries - total_queries)):
                    # Orthogonal step
                    noise = np.random.randn(*sample.shape)
                    noise = noise - np.dot(noise.flatten(), (adversarial - sample).flatten()) * (adversarial - sample) / (np.linalg.norm(adversarial - sample) ** 2 + 1e-10)
                    noise = noise / (np.linalg.norm(noise) + 1e-10) * step_size

                    candidate = adversarial + noise
                    candidate = np.clip(candidate, 0, 1)

                    cand_pred = self.target.predict(candidate.tolist())
                    cand_class = self._get_predicted_class(cand_pred)
                    total_queries += 1

                    if cand_class != orig_class:
                        # Move toward original
                        candidate = candidate - step_size * (candidate - sample) / (np.linalg.norm(candidate - sample) + 1e-10)
                        candidate = np.clip(candidate, 0, 1)

                        check_pred = self.target.predict(candidate.tolist())
                        check_class = self._get_predicted_class(check_pred)
                        total_queries += 1

                        if check_class != orig_class:
                            adversarial = candidate

                perturbation = adversarial - sample
                if np.linalg.norm(perturbation) < self.epsilon * np.sqrt(sample.size):
                    success_count += 1
                    perturbation_norms.append(np.linalg.norm(perturbation))

                    self.adversarial_examples.append(AdversarialExample(
                        original=sample,
                        adversarial=adversarial,
                        perturbation=perturbation,
                        original_prediction=orig_class,
                        adversarial_prediction=self._get_predicted_class(
                            self.target.predict(adversarial.tolist())
                        ),
                        l0_norm=np.count_nonzero(perturbation),
                        l2_norm=np.linalg.norm(perturbation),
                        linf_norm=np.max(np.abs(perturbation)),
                        queries_used=total_queries,
                        attack_method='BoundaryAttack',
                        success=True
                    ))

            except Exception as e:
                self.logger.debug(f"Boundary attack sample failed: {e}")

        duration = time.time() - start_time
        success_rate = success_count / len(samples) if samples.size > 0 else 0

        if success_rate > 0.2:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Vulnerable to Decision-Based Boundary Attack",
                category=AttackCategory.EVASION,
                severity=Severity.HIGH,
                description=f"The model is vulnerable to decision-based boundary attacks with {success_rate*100:.1f}% success rate. This attack only requires final decisions, not confidence scores.",
                evidence={
                    "success_rate": success_rate,
                    "queries_used": total_queries,
                    "samples_tested": len(samples)
                },
                remediation="Implement output randomization, add noise to decisions, or use ensemble methods.",
                cvss_score=7.5
            ))

        return TestResult(
            test_name="BoundaryAttack",
            success=True,
            attack_succeeded=success_rate > 0.1,
            metrics={
                "success_rate": success_rate,
                "queries_used": total_queries,
                "samples_tested": len(samples),
                "avg_perturbation_l2": np.mean(perturbation_norms) if perturbation_norms else 0
            },
            duration_seconds=duration,
            queries_used=total_queries
        )

    def test_hopskipjump(
        self,
        samples: Optional[np.ndarray] = None,
        max_queries: int = 5000
    ) -> TestResult:
        """
        HopSkipJump Attack
        Query-efficient decision-based attack
        """
        start_time = time.time()

        if samples is None:
            samples = self._generate_test_samples()

        success_count = 0
        total_queries = 0
        perturbation_norms = []

        for sample in samples:
            try:
                orig_pred = self.target.predict(sample.tolist())
                orig_class = self._get_predicted_class(orig_pred)
                total_queries += 1

                # Find initial adversarial
                adversarial = self._find_initial_adversarial(sample, orig_class)
                if adversarial is None:
                    continue
                total_queries += 100

                # Binary search and gradient estimation iterations
                for iteration in range(50):
                    if total_queries >= max_queries:
                        break

                    # Binary search to boundary
                    low, high = 0.0, 1.0
                    for _ in range(10):
                        mid = (low + high) / 2
                        candidate = sample + mid * (adversarial - sample)
                        cand_pred = self.target.predict(candidate.tolist())
                        cand_class = self._get_predicted_class(cand_pred)
                        total_queries += 1

                        if cand_class != orig_class:
                            high = mid
                            adversarial = candidate
                        else:
                            low = mid

                    # Estimate gradient at boundary using monte carlo
                    num_samples = 100
                    gradients = []
                    for _ in range(num_samples):
                        noise = np.random.randn(*sample.shape)
                        noise = noise / np.linalg.norm(noise)

                        delta = 0.01
                        sample_plus = adversarial + delta * noise
                        sample_plus = np.clip(sample_plus, 0, 1)

                        pred_plus = self.target.predict(sample_plus.tolist())
                        class_plus = self._get_predicted_class(pred_plus)
                        total_queries += 1

                        if class_plus != orig_class:
                            gradients.append(noise)
                        else:
                            gradients.append(-noise)

                    if gradients:
                        gradient = np.mean(gradients, axis=0)
                        gradient = gradient / (np.linalg.norm(gradient) + 1e-10)

                        # Step along gradient
                        step_size = np.linalg.norm(adversarial - sample) / 10
                        adversarial = adversarial - step_size * gradient
                        adversarial = np.clip(adversarial, 0, 1)

                # Check final result
                perturbation = adversarial - sample
                final_pred = self.target.predict(adversarial.tolist())
                final_class = self._get_predicted_class(final_pred)

                if final_class != orig_class:
                    success_count += 1
                    perturbation_norms.append(np.linalg.norm(perturbation))

                    self.adversarial_examples.append(AdversarialExample(
                        original=sample,
                        adversarial=adversarial,
                        perturbation=perturbation,
                        original_prediction=orig_class,
                        adversarial_prediction=final_class,
                        l0_norm=np.count_nonzero(perturbation),
                        l2_norm=np.linalg.norm(perturbation),
                        linf_norm=np.max(np.abs(perturbation)),
                        queries_used=total_queries,
                        attack_method='HopSkipJump',
                        success=True
                    ))

            except Exception as e:
                self.logger.debug(f"HopSkipJump sample failed: {e}")

        duration = time.time() - start_time
        success_rate = success_count / len(samples) if samples.size > 0 else 0

        if success_rate > 0.2:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Vulnerable to HopSkipJump Attack",
                category=AttackCategory.EVASION,
                severity=Severity.HIGH,
                description=f"The model is vulnerable to HopSkipJump attacks with {success_rate*100:.1f}% success rate. This is a query-efficient black-box attack.",
                evidence={
                    "success_rate": success_rate,
                    "queries_used": total_queries,
                    "samples_tested": len(samples)
                },
                remediation="Implement query throttling, detection mechanisms for adversarial query patterns, or certified defenses.",
                cvss_score=7.5
            ))

        return TestResult(
            test_name="HopSkipJump",
            success=True,
            attack_succeeded=success_rate > 0.1,
            metrics={
                "success_rate": success_rate,
                "queries_used": total_queries,
                "samples_tested": len(samples),
                "avg_perturbation_l2": np.mean(perturbation_norms) if perturbation_norms else 0
            },
            duration_seconds=duration,
            queries_used=total_queries
        )

    def _generate_test_samples(self, num_samples: int = 10) -> np.ndarray:
        """Generate random test samples"""
        # Default to image-like samples (3x224x224)
        shape = self.config.get('input_shape', (3, 224, 224))
        return np.random.rand(num_samples, *shape).astype(np.float32)

    def _get_predicted_class(self, prediction: Any) -> int:
        """Extract predicted class from model output"""
        if isinstance(prediction, dict):
            if 'class' in prediction:
                return prediction['class']
            if 'prediction' in prediction:
                return prediction['prediction']
            if 'probabilities' in prediction:
                return np.argmax(prediction['probabilities'])
            if 'logits' in prediction:
                return np.argmax(prediction['logits'])

        if isinstance(prediction, (list, np.ndarray)):
            return np.argmax(prediction)

        return int(prediction)

    def _estimate_gradient(self, sample: np.ndarray, target_class: int) -> np.ndarray:
        """Estimate gradient using finite differences"""
        gradient = np.zeros_like(sample)
        delta = 0.001

        # Sample gradient estimation (not computing full gradient for efficiency)
        indices = np.random.choice(sample.size, min(100, sample.size), replace=False)

        for idx in indices:
            flat_sample = sample.flatten()

            # Forward
            flat_sample_plus = flat_sample.copy()
            flat_sample_plus[idx] += delta
            sample_plus = flat_sample_plus.reshape(sample.shape)

            # Backward
            flat_sample_minus = flat_sample.copy()
            flat_sample_minus[idx] -= delta
            sample_minus = flat_sample_minus.reshape(sample.shape)

            # Get probabilities
            probs_plus = self.target.get_probabilities(sample_plus.tolist())
            probs_minus = self.target.get_probabilities(sample_minus.tolist())

            if probs_plus is not None and probs_minus is not None:
                # Gradient of loss with respect to target class
                grad = (probs_plus[target_class] - probs_minus[target_class]) / (2 * delta)
                gradient.flatten()[idx] = -grad  # Negative because we want to decrease confidence

        return gradient

    def _find_initial_adversarial(
        self,
        sample: np.ndarray,
        orig_class: int,
        max_attempts: int = 100
    ) -> Optional[np.ndarray]:
        """Find an initial adversarial example (different prediction)"""
        for _ in range(max_attempts):
            random_sample = np.random.rand(*sample.shape).astype(np.float32)
            pred = self.target.predict(random_sample.tolist())
            pred_class = self._get_predicted_class(pred)

            if pred_class != orig_class:
                return random_sample

        return None


if __name__ == "__main__":
    # Example usage
    from utils.base import APIModelInterface, setup_logging

    setup_logging()

    # Mock target for testing
    class MockModel(ModelInterface):
        def predict(self, input_data):
            return {"class": 0, "probabilities": [0.9, 0.1]}
        def get_probabilities(self, input_data):
            return [0.9, 0.1]
        def get_logits(self, input_data):
            return [2.0, -2.0]

    target = MockModel()
    output_dir = Path("/tmp/aiml_pentest_test")

    module = EvasionAttackModule(
        target=target,
        output_dir=output_dir,
        config={
            'epsilon': 0.1,
            'input_shape': (3, 32, 32)
        }
    )

    results = module.run_tests()
    for r in results:
        print(f"{r.test_name}: Success={r.attack_succeeded}, Rate={r.metrics.get('success_rate', 0):.2%}")
