#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Data Poisoning Assessment
Tests for training data poisoning vulnerabilities
"""

import time
import json
import hashlib
import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.base import (
    TestModule, ModelInterface, TestResult, Finding,
    Severity, AttackCategory
)


class PoisonType(Enum):
    LABEL_FLIP = "label_flip"
    BACKDOOR = "backdoor"
    CLEAN_LABEL = "clean_label"
    GRADIENT_BASED = "gradient_based"
    FEATURE_COLLISION = "feature_collision"


@dataclass
class PoisonSample:
    """A poisoned training sample"""
    original: np.ndarray
    poisoned: np.ndarray
    original_label: int
    target_label: int
    poison_type: PoisonType
    trigger_pattern: Optional[np.ndarray] = None


@dataclass
class PoisoningAssessment:
    """Results of poisoning feasibility assessment"""
    poison_type: PoisonType
    feasible: bool
    estimated_poison_rate: float
    detection_difficulty: str
    impact_description: str
    evidence: Dict[str, Any]


class DataPoisoningModule(TestModule):
    """
    Data poisoning assessment module
    Evaluates vulnerability to training data poisoning attacks
    """

    def __init__(
        self,
        target: ModelInterface,
        output_dir: Path,
        config: Optional[Dict] = None
    ):
        super().__init__(target, output_dir, config)

        self.num_classes = config.get('num_classes', 10)
        self.input_shape = config.get('input_shape', (3, 224, 224))

        # Backdoor trigger configuration
        self.trigger_size = config.get('trigger_size', 5)
        self.trigger_position = config.get('trigger_position', 'bottom_right')

        self.assessments: List[PoisoningAssessment] = []
        self.generated_poisons: List[PoisonSample] = []

    def run_tests(self) -> List[TestResult]:
        """Execute all data poisoning assessment tests"""
        results = []

        test_methods = [
            ('LabelFlipAssessment', self.assess_label_flip),
            ('BackdoorAssessment', self.assess_backdoor),
            ('CleanLabelAssessment', self.assess_clean_label),
            ('TriggerDetection', self.test_trigger_detection),
            ('PoisonRateEstimation', self.estimate_poison_rate),
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
        self._save_poison_samples()
        return results

    def assess_label_flip(self) -> TestResult:
        """
        Assess vulnerability to label flipping attacks
        Tests if model can be manipulated by mislabeled training data
        """
        start_time = time.time()

        # Generate test samples with different label scenarios
        num_samples = 100
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        # Get original predictions
        original_predictions = []
        for sample in samples[:20]:  # Use subset for efficiency
            try:
                pred = self.target.predict(sample.tolist())
                original_predictions.append(self._get_predicted_class(pred))
            except Exception as e:
                self.logger.debug(f"Prediction failed: {e}")

        # Analyze prediction distribution
        class_distribution = {}
        for pred in original_predictions:
            class_distribution[pred] = class_distribution.get(pred, 0) + 1

        # Calculate metrics
        majority_class_ratio = max(class_distribution.values()) / len(original_predictions) if original_predictions else 0
        class_imbalance = len(class_distribution) / self.num_classes

        # Assess vulnerability
        # Higher imbalance and concentration = more vulnerable to label flip
        vulnerability_score = majority_class_ratio * (1 - class_imbalance)

        assessment = PoisoningAssessment(
            poison_type=PoisonType.LABEL_FLIP,
            feasible=vulnerability_score > 0.3,
            estimated_poison_rate=min(0.3, vulnerability_score),
            detection_difficulty="Low" if class_imbalance < 0.5 else "Medium",
            impact_description=f"Label flipping could bias model toward majority class with {vulnerability_score*100:.1f}% effectiveness",
            evidence={
                "class_distribution": class_distribution,
                "majority_ratio": majority_class_ratio,
                "class_coverage": class_imbalance,
                "vulnerability_score": vulnerability_score
            }
        )

        self.assessments.append(assessment)

        if assessment.feasible:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Potentially Vulnerable to Label Flip Poisoning",
                category=AttackCategory.DATA_POISONING,
                severity=Severity.MEDIUM,
                description=f"Class distribution analysis suggests vulnerability to label flip attacks. Estimated poison rate needed: {assessment.estimated_poison_rate*100:.1f}%",
                evidence=assessment.evidence,
                remediation="Implement training data validation, label consistency checks, and data sanitization."
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="LabelFlipAssessment",
            success=True,
            attack_succeeded=assessment.feasible,
            metrics={
                "vulnerability_score": vulnerability_score,
                "estimated_poison_rate": assessment.estimated_poison_rate,
                "class_distribution": class_distribution
            },
            duration_seconds=duration,
            queries_used=len(original_predictions)
        )

    def assess_backdoor(self) -> TestResult:
        """
        Assess vulnerability to backdoor/trojan attacks
        Tests if hidden triggers could be embedded in model
        """
        start_time = time.time()

        # Generate clean samples
        num_samples = 50
        clean_samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        # Create trigger pattern
        trigger = self._create_trigger_pattern()

        # Apply trigger to samples
        triggered_samples = self._apply_trigger(clean_samples, trigger)

        # Analyze behavior difference
        clean_predictions = []
        triggered_predictions = []

        for clean, triggered in zip(clean_samples[:20], triggered_samples[:20]):
            try:
                clean_pred = self.target.predict(clean.tolist())
                triggered_pred = self.target.predict(triggered.tolist())

                clean_predictions.append(self._get_predicted_class(clean_pred))
                triggered_predictions.append(self._get_predicted_class(triggered_pred))
            except Exception as e:
                self.logger.debug(f"Prediction failed: {e}")

        # Calculate behavior change
        if clean_predictions and triggered_predictions:
            behavior_change = sum(
                1 for c, t in zip(clean_predictions, triggered_predictions)
                if c != t
            ) / len(clean_predictions)
        else:
            behavior_change = 0

        # If model already shows different behavior with triggers, it may be compromised
        # If behavior is same, it's resistant but poisoning is still feasible
        already_backdoored = behavior_change > 0.8

        # Generate sample backdoor poisons
        target_class = (np.bincount(clean_predictions).argmin()
                       if clean_predictions else 0)

        for i, (clean, triggered) in enumerate(zip(clean_samples[:5], triggered_samples[:5])):
            self.generated_poisons.append(PoisonSample(
                original=clean,
                poisoned=triggered,
                original_label=clean_predictions[i] if i < len(clean_predictions) else 0,
                target_label=target_class,
                poison_type=PoisonType.BACKDOOR,
                trigger_pattern=trigger
            ))

        assessment = PoisoningAssessment(
            poison_type=PoisonType.BACKDOOR,
            feasible=True,  # Backdoor attacks are generally feasible
            estimated_poison_rate=0.01 if already_backdoored else 0.05,
            detection_difficulty="High",
            impact_description="Backdoor triggers could cause targeted misclassification with high success rate",
            evidence={
                "trigger_behavior_change": behavior_change,
                "possibly_already_backdoored": already_backdoored,
                "trigger_size": self.trigger_size,
                "trigger_position": self.trigger_position
            }
        )

        self.assessments.append(assessment)

        if already_backdoored:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Potential Existing Backdoor Detected",
                category=AttackCategory.DATA_POISONING,
                severity=Severity.CRITICAL,
                description=f"Model shows {behavior_change*100:.1f}% behavior change with trigger patterns, suggesting possible existing backdoor.",
                evidence=assessment.evidence,
                remediation="Conduct full backdoor detection analysis using Neural Cleanse or similar tools.",
                cvss_score=9.0
            ))
        else:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Susceptible to Backdoor Poisoning",
                category=AttackCategory.DATA_POISONING,
                severity=Severity.HIGH,
                description="Backdoor poisoning attack is feasible. Generated sample poison data for demonstration.",
                evidence=assessment.evidence,
                remediation="Implement trigger detection, pruning, and fine-tuning defenses."
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="BackdoorAssessment",
            success=True,
            attack_succeeded=True,  # Backdoor is always theoretically feasible
            metrics={
                "behavior_change_with_trigger": behavior_change,
                "possibly_backdoored": already_backdoored,
                "poison_samples_generated": len(self.generated_poisons)
            },
            duration_seconds=duration,
            queries_used=len(clean_predictions) * 2
        )

    def assess_clean_label(self) -> TestResult:
        """
        Assess vulnerability to clean-label poisoning
        No label change required - relies on feature collision
        """
        start_time = time.time()

        # Generate base samples
        num_samples = 30
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        # Get predictions and probabilities
        predictions = []
        confidence_scores = []

        for sample in samples:
            try:
                pred = self.target.predict(sample.tolist())
                probs = self.target.get_probabilities(sample.tolist())

                pred_class = self._get_predicted_class(pred)
                predictions.append(pred_class)

                if probs:
                    confidence_scores.append(max(probs))
            except Exception as e:
                self.logger.debug(f"Prediction failed: {e}")

        # Analyze confidence distribution
        avg_confidence = np.mean(confidence_scores) if confidence_scores else 0
        confidence_std = np.std(confidence_scores) if confidence_scores else 0

        # Low confidence samples are better targets for clean-label attacks
        low_confidence_ratio = sum(
            1 for c in confidence_scores if c < 0.7
        ) / len(confidence_scores) if confidence_scores else 0

        # Generate clean-label poison candidates
        for i, sample in enumerate(samples[:5]):
            if i < len(predictions):
                # Create perturbation for feature collision
                perturbation = self._generate_collision_perturbation(sample)

                self.generated_poisons.append(PoisonSample(
                    original=sample,
                    poisoned=sample + perturbation,
                    original_label=predictions[i],
                    target_label=predictions[i],  # Same label (clean-label)
                    poison_type=PoisonType.CLEAN_LABEL
                ))

        # Assess feasibility
        feasibility_score = low_confidence_ratio * (1 - avg_confidence)

        assessment = PoisoningAssessment(
            poison_type=PoisonType.CLEAN_LABEL,
            feasible=feasibility_score > 0.1,
            estimated_poison_rate=max(0.05, 0.3 * (1 - avg_confidence)),
            detection_difficulty="Very High",
            impact_description="Clean-label attacks are harder to detect as poisoned samples maintain correct labels",
            evidence={
                "avg_confidence": avg_confidence,
                "confidence_std": confidence_std,
                "low_confidence_ratio": low_confidence_ratio,
                "feasibility_score": feasibility_score
            }
        )

        self.assessments.append(assessment)

        if assessment.feasible:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Model Vulnerable to Clean-Label Poisoning",
                category=AttackCategory.DATA_POISONING,
                severity=Severity.HIGH,
                description=f"Clean-label poisoning is feasible with {low_confidence_ratio*100:.1f}% of samples showing low confidence.",
                evidence=assessment.evidence,
                remediation="Implement spectral signatures defense, influence function analysis, or certified data poisoning defenses."
            ))

        duration = time.time() - start_time

        return TestResult(
            test_name="CleanLabelAssessment",
            success=True,
            attack_succeeded=assessment.feasible,
            metrics={
                "avg_confidence": avg_confidence,
                "low_confidence_ratio": low_confidence_ratio,
                "feasibility_score": feasibility_score
            },
            duration_seconds=duration,
            queries_used=len(predictions)
        )

    def test_trigger_detection(self) -> TestResult:
        """
        Test if model shows sensitivity to common backdoor trigger patterns
        May indicate existing backdoor
        """
        start_time = time.time()

        trigger_patterns = [
            ("pixel_pattern", self._create_pixel_trigger),
            ("patch", self._create_patch_trigger),
            ("blend", self._create_blend_trigger),
            ("noise", self._create_noise_trigger),
        ]

        results = {}
        base_sample = np.random.rand(*self.input_shape).astype(np.float32)

        try:
            base_pred = self.target.predict(base_sample.tolist())
            base_class = self._get_predicted_class(base_pred)
        except Exception as e:
            self.logger.error(f"Base prediction failed: {e}")
            return TestResult(
                test_name="TriggerDetection",
                success=False,
                attack_succeeded=False,
                metrics={},
                duration_seconds=0,
                error=str(e)
            )

        suspicious_triggers = []

        for trigger_name, trigger_func in trigger_patterns:
            trigger = trigger_func()
            triggered = self._apply_single_trigger(base_sample, trigger)

            try:
                triggered_pred = self.target.predict(triggered.tolist())
                triggered_class = self._get_predicted_class(triggered_pred)

                changed = triggered_class != base_class
                results[trigger_name] = {
                    "changed_prediction": changed,
                    "base_class": base_class,
                    "triggered_class": triggered_class
                }

                if changed:
                    suspicious_triggers.append(trigger_name)

            except Exception as e:
                self.logger.debug(f"Trigger test {trigger_name} failed: {e}")
                results[trigger_name] = {"error": str(e)}

        duration = time.time() - start_time

        if suspicious_triggers:
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Suspicious Trigger Sensitivity Detected",
                category=AttackCategory.DATA_POISONING,
                severity=Severity.HIGH,
                description=f"Model shows prediction changes with trigger patterns: {', '.join(suspicious_triggers)}",
                evidence={"trigger_results": results},
                remediation="Run full backdoor detection analysis (Neural Cleanse, STRIP, etc.)"
            ))

        return TestResult(
            test_name="TriggerDetection",
            success=True,
            attack_succeeded=len(suspicious_triggers) > 0,
            metrics={
                "triggers_tested": len(trigger_patterns),
                "suspicious_triggers": len(suspicious_triggers),
                "trigger_results": results
            },
            duration_seconds=duration,
            queries_used=len(trigger_patterns) + 1
        )

    def estimate_poison_rate(self) -> TestResult:
        """
        Estimate required poisoning rate for successful attack
        Based on model confidence and decision boundary analysis
        """
        start_time = time.time()

        # Sample decision boundary
        num_samples = 100
        samples = np.random.rand(num_samples, *self.input_shape).astype(np.float32)

        predictions = []
        confidences = []

        for sample in samples:
            try:
                probs = self.target.get_probabilities(sample.tolist())
                if probs:
                    predictions.append(np.argmax(probs))
                    confidences.append(sorted(probs, reverse=True))
            except Exception as e:
                self.logger.debug(f"Sampling failed: {e}")

        if not confidences:
            return TestResult(
                test_name="PoisonRateEstimation",
                success=False,
                attack_succeeded=False,
                metrics={},
                duration_seconds=0,
                error="Could not get probability outputs"
            )

        # Calculate margin (difference between top-2 classes)
        margins = [c[0] - c[1] if len(c) > 1 else c[0] for c in confidences]
        avg_margin = np.mean(margins)
        avg_confidence = np.mean([c[0] for c in confidences])

        # Estimate poison rate based on margin
        # Lower margin = easier to flip = lower poison rate needed
        estimated_rate = {
            "label_flip": max(0.01, 0.3 * avg_margin),
            "backdoor": max(0.001, 0.05 * avg_margin),
            "clean_label": max(0.05, 0.5 * avg_margin),
        }

        duration = time.time() - start_time

        return TestResult(
            test_name="PoisonRateEstimation",
            success=True,
            attack_succeeded=True,
            metrics={
                "average_margin": avg_margin,
                "average_confidence": avg_confidence,
                "estimated_rates": estimated_rate,
                "samples_analyzed": len(confidences)
            },
            duration_seconds=duration,
            queries_used=len(confidences)
        )

    def _create_trigger_pattern(self) -> np.ndarray:
        """Create default trigger pattern"""
        trigger = np.zeros(self.input_shape, dtype=np.float32)

        # Place trigger based on configuration
        if len(self.input_shape) == 3:  # CHW format
            c, h, w = self.input_shape
            if self.trigger_position == 'bottom_right':
                trigger[:, h-self.trigger_size:, w-self.trigger_size:] = 1.0
            elif self.trigger_position == 'top_left':
                trigger[:, :self.trigger_size, :self.trigger_size] = 1.0

        return trigger

    def _apply_trigger(self, samples: np.ndarray, trigger: np.ndarray) -> np.ndarray:
        """Apply trigger to batch of samples"""
        triggered = samples.copy()
        mask = trigger > 0
        for i in range(len(triggered)):
            triggered[i][mask] = trigger[mask]
        return triggered

    def _apply_single_trigger(self, sample: np.ndarray, trigger: np.ndarray) -> np.ndarray:
        """Apply trigger to single sample"""
        triggered = sample.copy()
        mask = trigger > 0
        triggered[mask] = trigger[mask]
        return triggered

    def _create_pixel_trigger(self) -> np.ndarray:
        """Create pixel-based trigger"""
        trigger = np.zeros(self.input_shape, dtype=np.float32)
        if len(self.input_shape) == 3:
            c, h, w = self.input_shape
            trigger[:, h-3:h, w-3:w] = 1.0
        return trigger

    def _create_patch_trigger(self) -> np.ndarray:
        """Create patch-based trigger"""
        trigger = np.zeros(self.input_shape, dtype=np.float32)
        if len(self.input_shape) == 3:
            c, h, w = self.input_shape
            # Checkerboard pattern
            for i in range(5):
                for j in range(5):
                    if (i + j) % 2 == 0:
                        trigger[:, h-5+i:h-5+i+1, w-5+j:w-5+j+1] = 1.0
        return trigger

    def _create_blend_trigger(self) -> np.ndarray:
        """Create blend/watermark trigger"""
        trigger = np.random.rand(*self.input_shape).astype(np.float32) * 0.1
        return trigger

    def _create_noise_trigger(self) -> np.ndarray:
        """Create noise-based trigger"""
        trigger = np.random.randn(*self.input_shape).astype(np.float32) * 0.05
        return trigger

    def _generate_collision_perturbation(self, sample: np.ndarray) -> np.ndarray:
        """Generate perturbation for feature collision attack"""
        return np.random.randn(*sample.shape).astype(np.float32) * 0.01

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

    def _save_poison_samples(self):
        """Save generated poison samples"""
        if not self.generated_poisons:
            return

        samples_dir = self.output_dir / "poison_samples"
        samples_dir.mkdir(exist_ok=True)

        manifest = []
        for i, poison in enumerate(self.generated_poisons):
            sample_data = {
                "index": i,
                "poison_type": poison.poison_type.value,
                "original_label": int(poison.original_label),
                "target_label": int(poison.target_label),
                "perturbation_norm": float(np.linalg.norm(poison.poisoned - poison.original))
            }
            manifest.append(sample_data)

            # Save arrays
            np.save(samples_dir / f"original_{i}.npy", poison.original)
            np.save(samples_dir / f"poisoned_{i}.npy", poison.poisoned)
            if poison.trigger_pattern is not None:
                np.save(samples_dir / f"trigger_{i}.npy", poison.trigger_pattern)

        with open(samples_dir / "manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)

        self.logger.info(f"Saved {len(manifest)} poison samples to {samples_dir}")


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
    output_dir = Path("/tmp/aiml_pentest_poison")

    module = DataPoisoningModule(
        target=target,
        output_dir=output_dir,
        config={'num_classes': 10, 'input_shape': (3, 32, 32)}
    )

    results = module.run_tests()
    for r in results:
        print(f"{r.test_name}: Feasible={r.attack_succeeded}")
