#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Membership Inference Attacks
Tests privacy vulnerabilities through membership inference

QUARANTINE NOTICE
-----------------
This module is QUARANTINED experimental scaffolding.  It is NOT wired into
the CLI (`_get_module` loaders) and must NOT be added until a real rebuild is
complete (see Phase 7 of docs/REMEDIATION-PLAN-08JUN2026.md).

Reasons:
  - Membership labels are synthetic (assigned by list index), NOT derived from
    real training/non-training data splits.
  - Attack accuracy metrics reflect noise on random inputs, not real privacy
    leakage.  Producing findings from this module is misleading.
  - All four test methods call target.get_probabilities() with numpy arrays
    which makes the module numpy-DEPENDENT and unsuitable for numpy-free paths.

The individual test_* methods may still be called directly for unit testing of
the underlying mechanics (as long as tests are aware of the synthetic-label
caveat).  The aggregate run_tests() entrypoint is gated by
self.config.get('allow_synthetic', False) to prevent accidental use.
"""

import time
import json
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

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


@dataclass
class MembershipResult:
    """Result of membership inference attack"""
    attack_accuracy: float
    tpr_at_low_fpr: float  # True positive rate at 0.1% FPR
    auc_score: float
    advantage: float  # Over random guessing
    samples_tested: int


class MembershipInferenceModule(TestModule):
    """
    Membership Inference Attack Module
    Tests whether training data membership can be inferred
    """

    def __init__(
        self,
        target: ModelInterface,
        output_dir: Path,
        config: Optional[Dict] = None
    ):
        super().__init__(target, output_dir, config)
        self.logger.warning(_EXPERIMENTAL_BANNER)

        self.num_classes = config.get('num_classes', 10)
        self.input_shape = config.get('input_shape', (3, 224, 224))
        self.num_shadow_models = config.get('num_shadow_models', 3)

        self.attack_results: List[MembershipResult] = []

    def run_tests(self) -> List[TestResult]:
        """Execute membership inference tests.

        Gated by config['allow_synthetic'].  By default this returns an empty
        list and logs a warning to prevent misleading findings based on
        synthetic membership labels.  Pass allow_synthetic=True only in
        contexts where the caller explicitly acknowledges the scaffold
        limitation (e.g. unit tests exercising the mechanics).
        """
        if not self.config.get('allow_synthetic', False):
            self.logger.warning(
                "MembershipInferenceModule.run_tests() is QUARANTINED: "
                "membership labels are synthetic (not derived from real training data). "
                "No findings will be emitted.  Set config['allow_synthetic']=True "
                "to run anyway (e.g. in unit tests).  "
                "See docs/REMEDIATION-PLAN-08JUN2026.md Phase 7."
            )
            return []

        results = []

        test_methods = [
            ('ThresholdAttack', self.test_threshold_attack),
            ('ShadowModelAttack', self.test_shadow_model_attack),
            ('LabelOnlyAttack', self.test_label_only_attack),
            ('EntropyAttack', self.test_entropy_attack),
        ]

        for name, method in test_methods:
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

        self.save_results()
        return results

    def test_threshold_attack(self) -> TestResult:
        """
        Threshold-based membership inference
        Uses confidence scores to infer membership
        """
        start_time = time.time()

        # Generate test samples (simulating members and non-members)
        num_samples = 200
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        # Simulate member/non-member split (first half "members")
        member_indices = set(range(num_samples // 2))

        confidences = []
        true_labels = []

        for i, sample in enumerate(samples):
            try:
                probs = self.target.get_probabilities(sample.tolist())
                if probs:
                    max_conf = max(probs)
                    confidences.append(max_conf)
                    true_labels.append(1 if i in member_indices else 0)
            except Exception as e:
                self.logger.debug(f"Sample {i} failed: {e}")

        if len(confidences) < 10:
            return TestResult(
                test_name="ThresholdAttack",
                success=False,
                attack_succeeded=False,
                metrics={},
                duration_seconds=0,
                error="Not enough valid samples"
            )

        # Find optimal threshold
        thresholds = np.percentile(confidences, range(0, 101, 5))
        best_accuracy = 0.5
        best_threshold = 0.5

        for threshold in thresholds:
            predictions = [1 if c >= threshold else 0 for c in confidences]
            accuracy = sum(p == t for p, t in zip(predictions, true_labels)) / len(predictions)
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_threshold = threshold

        # Calculate metrics
        predictions = [1 if c >= best_threshold else 0 for c in confidences]

        # True positive rate at low false positive rate
        member_confs = [c for c, l in zip(confidences, true_labels) if l == 1]
        non_member_confs = [c for c, l in zip(confidences, true_labels) if l == 0]

        if non_member_confs:
            fpr_threshold = np.percentile(non_member_confs, 99.9)  # 0.1% FPR
            tpr_at_low_fpr = sum(1 for c in member_confs if c >= fpr_threshold) / len(member_confs) if member_confs else 0
        else:
            tpr_at_low_fpr = 0

        # Calculate AUC approximation
        auc = self._calculate_auc(confidences, true_labels)

        advantage = best_accuracy - 0.5

        result = MembershipResult(
            attack_accuracy=best_accuracy,
            tpr_at_low_fpr=tpr_at_low_fpr,
            auc_score=auc,
            advantage=advantage,
            samples_tested=len(confidences)
        )

        self.attack_results.append(result)

        duration = time.time() - start_time

        if best_accuracy > 0.6:
            evidence = asdict(result)
            evidence["measurement_type"] = "heuristic"
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Membership Inference Vulnerability (Threshold Attack)",
                category=AttackCategory.MEMBERSHIP_INFERENCE,
                severity=Severity.INFO,
                description=f"Heuristic estimate: threshold attack achieves {best_accuracy*100:.1f}% accuracy (advantage: {advantage*100:.1f}%) on synthetic membership labels assigned by list index — membership labels are not derived from real training data; this is a research-scaffold estimate, not a real attack result.",
                evidence=evidence,
                remediation="Implement differential privacy, output perturbation, or regularization techniques."
            ))

        return TestResult(
            test_name="ThresholdAttack",
            success=True,
            attack_succeeded=False,  # Research-scaffold: synthetic membership labels, not real training data; must not inflate rollup
            metrics={
                "attack_accuracy": best_accuracy,
                "optimal_threshold": best_threshold,
                "tpr_at_0.1_fpr": tpr_at_low_fpr,
                "auc": auc,
                "advantage": advantage
            },
            duration_seconds=duration,
            queries_used=len(samples)
        )

    def test_shadow_model_attack(self) -> TestResult:
        """
        Shadow model membership inference
        Train shadow models to learn membership patterns
        """
        start_time = time.time()

        # Simulate shadow model training and attack
        # In real implementation, would train actual shadow models

        num_samples = 100
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        # Collect features for attack model
        features = []
        true_membership = []

        for i, sample in enumerate(samples):
            try:
                probs = self.target.get_probabilities(sample.tolist())
                if probs:
                    # Feature vector: sorted probabilities
                    sorted_probs = sorted(probs, reverse=True)

                    # Features: top-k probs, entropy, max conf
                    feature_vec = [
                        sorted_probs[0] if len(sorted_probs) > 0 else 0,  # Max
                        sorted_probs[1] if len(sorted_probs) > 1 else 0,  # Second
                        sorted_probs[0] - sorted_probs[1] if len(sorted_probs) > 1 else 0,  # Margin
                        self._entropy(probs),  # Entropy
                    ]

                    features.append(feature_vec)
                    # Simulate membership (would be from shadow models)
                    true_membership.append(1 if i < num_samples // 2 else 0)

            except Exception as e:
                self.logger.debug(f"Sample failed: {e}")

        if len(features) < 10:
            return TestResult(
                test_name="ShadowModelAttack",
                success=False,
                attack_succeeded=False,
                metrics={},
                duration_seconds=0,
                error="Not enough valid samples"
            )

        # Simple attack model (threshold on margin)
        margins = [f[2] for f in features]  # Margin feature
        member_margins = [m for m, l in zip(margins, true_membership) if l == 1]
        nonmember_margins = [m for m, l in zip(margins, true_membership) if l == 0]

        # Calculate attack accuracy using margin threshold
        if member_margins and nonmember_margins:
            threshold = (np.mean(member_margins) + np.mean(nonmember_margins)) / 2
            predictions = [1 if m >= threshold else 0 for m in margins]
            accuracy = sum(p == t for p, t in zip(predictions, true_membership)) / len(predictions)
        else:
            accuracy = 0.5

        auc = self._calculate_auc(margins, true_membership)
        advantage = accuracy - 0.5

        result = MembershipResult(
            attack_accuracy=accuracy,
            tpr_at_low_fpr=0,  # Would calculate with full implementation
            auc_score=auc,
            advantage=advantage,
            samples_tested=len(features)
        )

        self.attack_results.append(result)

        duration = time.time() - start_time

        if accuracy > 0.6:
            evidence = asdict(result)
            evidence["measurement_type"] = "heuristic"
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Membership Inference Vulnerability (Shadow Model)",
                category=AttackCategory.MEMBERSHIP_INFERENCE,
                severity=Severity.INFO,
                description=f"Heuristic estimate: shadow model attack achieves {accuracy*100:.1f}% accuracy on synthetic membership labels assigned by list index — no shadow model was trained and membership labels are not derived from real training data; this is a research-scaffold estimate, not a real attack result.",
                evidence=evidence,
                remediation="Use differential privacy during training, implement membership inference defenses."
            ))

        return TestResult(
            test_name="ShadowModelAttack",
            success=True,
            attack_succeeded=False,  # Research-scaffold: no shadow model trained, synthetic membership labels; must not inflate rollup
            metrics={
                "attack_accuracy": accuracy,
                "auc": auc,
                "advantage": advantage,
                "shadow_models_simulated": self.num_shadow_models
            },
            duration_seconds=duration,
            queries_used=len(samples)
        )

    def test_label_only_attack(self) -> TestResult:
        """
        Label-only membership inference
        Works without confidence scores
        """
        start_time = time.time()

        num_samples = 100
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        # Test prediction consistency under augmentation
        consistency_scores = []
        true_membership = []

        for i, sample in enumerate(samples):
            consistencies = []

            try:
                # Get base prediction
                base_pred = self.target.predict(sample.tolist())
                base_class = self._get_predicted_class(base_pred)

                # Test with augmentations
                num_augmentations = 10
                for _ in range(num_augmentations):
                    # Add small noise
                    augmented = sample + np.random.randn(*sample.shape) * 0.01
                    augmented = np.clip(augmented, 0, 1)

                    aug_pred = self.target.predict(augmented.tolist())
                    aug_class = self._get_predicted_class(aug_pred)

                    consistencies.append(1 if aug_class == base_class else 0)

                consistency = np.mean(consistencies)
                consistency_scores.append(consistency)
                true_membership.append(1 if i < num_samples // 2 else 0)

            except Exception as e:
                self.logger.debug(f"Sample failed: {e}")

        if len(consistency_scores) < 10:
            return TestResult(
                test_name="LabelOnlyAttack",
                success=False,
                attack_succeeded=False,
                metrics={},
                duration_seconds=0,
                error="Not enough valid samples"
            )

        # Members typically have higher consistency
        threshold = np.median(consistency_scores)
        predictions = [1 if c >= threshold else 0 for c in consistency_scores]
        accuracy = sum(p == t for p, t in zip(predictions, true_membership)) / len(predictions)

        auc = self._calculate_auc(consistency_scores, true_membership)
        advantage = accuracy - 0.5

        result = MembershipResult(
            attack_accuracy=accuracy,
            tpr_at_low_fpr=0,
            auc_score=auc,
            advantage=advantage,
            samples_tested=len(consistency_scores)
        )

        self.attack_results.append(result)

        duration = time.time() - start_time

        if accuracy > 0.55:
            evidence = asdict(result)
            evidence["measurement_type"] = "heuristic"
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Membership Inference Vulnerability (Label-Only)",
                category=AttackCategory.MEMBERSHIP_INFERENCE,
                severity=Severity.INFO,
                description=f"Heuristic estimate: label-only attack achieves {accuracy*100:.1f}% accuracy on synthetic membership labels assigned by list index — membership labels are not derived from real training data; this is a research-scaffold estimate, not a real attack result.",
                evidence=evidence,
                remediation="Add noise to predictions, implement prediction consistency randomization."
            ))

        return TestResult(
            test_name="LabelOnlyAttack",
            success=True,
            attack_succeeded=False,  # Research-scaffold: synthetic membership labels, not real training data; must not inflate rollup
            metrics={
                "attack_accuracy": accuracy,
                "auc": auc,
                "advantage": advantage,
                "augmentations_per_sample": 10
            },
            duration_seconds=duration,
            queries_used=len(samples) * 11  # Base + 10 augmentations
        )

    def test_entropy_attack(self) -> TestResult:
        """
        Entropy-based membership inference
        Members typically have lower prediction entropy
        """
        start_time = time.time()

        num_samples = 100
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        entropies = []
        true_membership = []

        for i, sample in enumerate(samples):
            try:
                probs = self.target.get_probabilities(sample.tolist())
                if probs:
                    entropy = self._entropy(probs)
                    entropies.append(entropy)
                    true_membership.append(1 if i < num_samples // 2 else 0)
            except Exception as e:
                self.logger.debug(f"Sample failed: {e}")

        if len(entropies) < 10:
            return TestResult(
                test_name="EntropyAttack",
                success=False,
                attack_succeeded=False,
                metrics={},
                duration_seconds=0,
                error="Not enough valid samples"
            )

        # Lower entropy = more likely member (model more confident)
        # Invert entropy for prediction
        inv_entropies = [1 - e for e in entropies]

        threshold = np.median(inv_entropies)
        predictions = [1 if ie >= threshold else 0 for ie in inv_entropies]
        accuracy = sum(p == t for p, t in zip(predictions, true_membership)) / len(predictions)

        auc = self._calculate_auc(inv_entropies, true_membership)
        advantage = accuracy - 0.5

        result = MembershipResult(
            attack_accuracy=accuracy,
            tpr_at_low_fpr=0,
            auc_score=auc,
            advantage=advantage,
            samples_tested=len(entropies)
        )

        self.attack_results.append(result)

        duration = time.time() - start_time

        if accuracy > 0.55:
            evidence = asdict(result)
            evidence["measurement_type"] = "heuristic"
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Membership Inference Vulnerability (Entropy)",
                category=AttackCategory.MEMBERSHIP_INFERENCE,
                severity=Severity.INFO,
                description=f"Heuristic estimate: entropy-based attack achieves {accuracy*100:.1f}% accuracy on synthetic membership labels assigned by list index — membership labels are not derived from real training data; this is a research-scaffold estimate, not a real attack result.",
                evidence=evidence,
                remediation="Temperature scaling, confidence calibration, or output perturbation."
            ))

        return TestResult(
            test_name="EntropyAttack",
            success=True,
            attack_succeeded=False,  # Research-scaffold: synthetic membership labels, not real training data; must not inflate rollup
            metrics={
                "attack_accuracy": accuracy,
                "avg_entropy": np.mean(entropies),
                "auc": auc,
                "advantage": advantage
            },
            duration_seconds=duration,
            queries_used=len(samples)
        )

    def _get_predicted_class(self, prediction: Any) -> int:
        """Extract predicted class"""
        if isinstance(prediction, dict):
            if 'class' in prediction:
                return prediction['class']
            if 'probabilities' in prediction:
                return np.argmax(prediction['probabilities'])
        if isinstance(prediction, (list, np.ndarray)):
            return np.argmax(prediction)
        return int(prediction)

    def _entropy(self, probs: List[float]) -> float:
        """Calculate entropy of probability distribution"""
        probs = np.array(probs) + 1e-10
        return -np.sum(probs * np.log2(probs))

    def _calculate_auc(self, scores: List[float], labels: List[int]) -> float:
        """Calculate AUC score"""
        if not scores or not labels:
            return 0.5

        # Simple AUC calculation
        pos_scores = [s for s, l in zip(scores, labels) if l == 1]
        neg_scores = [s for s, l in zip(scores, labels) if l == 0]

        if not pos_scores or not neg_scores:
            return 0.5

        correct = 0
        total = len(pos_scores) * len(neg_scores)

        for ps in pos_scores:
            for ns in neg_scores:
                if ps > ns:
                    correct += 1
                elif ps == ns:
                    correct += 0.5

        return correct / total if total > 0 else 0.5


if __name__ == "__main__":
    from utils.base import setup_logging

    setup_logging()

    class MockModel(ModelInterface):
        def predict(self, input_data):
            return {"class": np.random.randint(0, 10)}
        def get_probabilities(self, input_data):
            probs = np.random.dirichlet(np.ones(10))
            return probs.tolist()
        def get_logits(self, input_data):
            return list(np.random.randn(10))

    target = MockModel()
    output_dir = Path("/tmp/aiml_pentest_membership")

    module = MembershipInferenceModule(
        target=target,
        output_dir=output_dir,
        config={'num_classes': 10, 'input_shape': (3, 32, 32)}
    )

    results = module.run_tests()
    for r in results:
        print(f"{r.test_name}: Accuracy={r.metrics.get('attack_accuracy', 0):.2%}")
