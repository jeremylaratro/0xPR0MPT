#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Membership Inference Attacks
Tests privacy vulnerabilities through membership inference

SCOPE
-----
This module provides TWO distinct execution paths:

  1. REAL PATH  — ``run_real_inference(member_samples, non_member_samples)``
     An honest, measurement-grade attack on caller-supplied data.  Ground-truth
     membership is provided by the caller (confirmed members vs. confirmed
     non-members).  A calibration/test split is used to fit the decision
     threshold on held-out calibration data and report advantage/AUC on a
     disjoint test set.  Severity is derived from the MEASURED advantage on the
     test set.  This path is scoped to CLASSIFIER targets that expose
     ``get_probabilities()``; LLM endpoints that return ``None`` for
     probabilities are out of scope and receive an INFO finding stating this.

  2. SYNTHETIC PATH  — ``run_tests()``
     Still QUARANTINED scaffolding.  Membership labels are assigned by list
     index (synthetic, not derived from real training data).  This path is
     gated by ``config['allow_synthetic']=True`` and emits only INFO findings
     regardless.  See docs/REMEDIATION-PLAN-08JUN2026.md Phase 7.

HONESTY GATE (real path)
------------------------
``run_real_inference()`` will NOT emit any HIGH/MEDIUM/LOW finding unless:
  - ``member_samples`` and ``non_member_samples`` are both supplied
  - Each set has at least ``MIN_REAL_SAMPLES`` (20) entries
  - The target's ``get_probabilities()`` returns a non-None probability vector

Severity scale (based on balanced-accuracy advantage = accuracy − 0.5):
  advantage >= 0.30  → HIGH   (strong privacy leak, high TPR)
  advantage >= 0.15  → MEDIUM (moderate leak worth investigating)
  advantage >= 0.10  → LOW    (weak but detectable signal)
  advantage <  0.10  → INFO   (no meaningful leakage detected)

LABEL-LEAKAGE CONTRACT
-----------------------
All per-sample attack statistics are computed by MODULE-LEVEL PURE FUNCTIONS
(``_stat_max_confidence``, ``_stat_neg_entropy``) that accept ONLY the
probability vector returned by the model — they receive NO membership label.
Labels are used exclusively to (i) fit the decision threshold on the
calibration split and (ii) score advantage/AUC on the disjoint test split.
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

# Minimum number of confirmed-member AND confirmed-non-member samples required
# before run_real_inference() may emit a non-INFO finding.  Below this threshold
# the calibration/test split produces too few test samples to measure advantage
# reliably (e.g. 20 each → 10 per class in the test split, std ≈ 0.11).
MIN_REAL_SAMPLES: int = 20

# Advantage severity thresholds (advantage = balanced_accuracy − 0.5, range 0–0.5)
# These are intentionally conservative — a non-INFO finding requires a clear,
# reproducible signal above the noise floor for a given sample size.
_ADV_HIGH: float = 0.30    # advantage >= 0.30 → HIGH
_ADV_MEDIUM: float = 0.15  # advantage >= 0.15 → MEDIUM
_ADV_LOW: float = 0.10     # advantage >= 0.10 → LOW
                            # advantage <  0.10 → INFO


# ---------------------------------------------------------------------------
# MODULE-LEVEL PURE STATISTIC FUNCTIONS
# These accept ONLY a probability vector.  They NEVER receive a membership
# label.  Keeping them module-level and label-free is the structural proof of
# the label-leakage contract — they can be imported and called in isolation
# in tests without any membership context.
# ---------------------------------------------------------------------------

def _stat_max_confidence(probs: List[float]) -> float:
    """Max-confidence statistic.  Higher → more member-like.
    Members in overfit models typically have a higher max softmax probability."""
    return float(max(probs))


def _stat_neg_entropy(probs: List[float]) -> float:
    """Negative-entropy statistic.  Higher → more member-like (lower entropy).
    Members produce lower-entropy (more peaked) distributions in overfit models.
    Using negative entropy (not 1-entropy) avoids the >2-class scaling issue."""
    p = np.array(probs, dtype=np.float64) + 1e-12  # numerical guard
    h = -np.sum(p * np.log2(p))
    return float(-h)  # negate: higher value = lower entropy = more member-like


def _stat_modified_entropy(probs: List[float]) -> float:
    """Modified-entropy (Mentr) statistic — Song & Mittal 2021.
    Uses the predicted class label (argmax) as a proxy for the true label, so
    it requires no ground-truth class label from the caller.
    Higher → more member-like."""
    p = np.array(probs, dtype=np.float64) + 1e-12
    y_hat = int(np.argmax(p))
    # Mentr = -[ (1 - p_yhat)*log(p_yhat) + sum_{j != yhat} p_j * log(1 - p_j) ]
    p_yhat = p[y_hat]
    term_correct = (1.0 - p_yhat) * np.log2(p_yhat)
    other_mask = np.ones(len(p), dtype=bool)
    other_mask[y_hat] = False
    term_others = np.sum(p[other_mask] * np.log2(1.0 - p[other_mask] + 1e-12))
    mentr = -(term_correct + term_others)
    return float(-mentr)  # negate: lower Mentr → more member-like; we negate for "higher = member"


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

    # ------------------------------------------------------------------
    # REAL MEASUREMENT PATH — Phase 7 build
    # ------------------------------------------------------------------

    def run_real_inference(
        self,
        member_samples: List[Any],
        non_member_samples: List[Any],
        seed: Optional[int] = None,
    ) -> List[TestResult]:
        """Run membership-inference attacks on caller-supplied confirmed data.

        Parameters
        ----------
        member_samples:
            Inputs that are CONFIRMED members of the target model's training set.
            The caller is responsible for ground-truth correctness.
        non_member_samples:
            Inputs that are CONFIRMED non-members (held-out / unseen by training).
            The two sets are assumed DISJOINT; passing the same sample as both a
            member and a non-member is a caller-contract violation and is not
            detected here.
        seed:
            Optional integer seed for the calibration/test split RNG.  Passing
            the same seed produces deterministic results.  Uses a LOCAL
            ``np.random.RandomState`` — does NOT mutate the global numpy state.

        Returns
        -------
        List[TestResult]
            One TestResult per attack variant.  Findings are emitted onto
            ``self.findings`` and attached to the relevant TestResult when
            advantage on the TEST split is non-trivial.  Returns an INFO-only
            list if the honesty gate is not cleared.

        HONESTY GATE
        ------------
        Returns a single INFO result (no HIGH/MEDIUM/LOW finding) if:
          - Either sample set is empty or smaller than MIN_REAL_SAMPLES (20).
          - The target's get_probabilities() returns None for a probe sample
            (e.g. LLMInterface targets — out of scope for this implementation).

        SPLIT DISCIPLINE
        ----------------
        Members and non-members are each shuffled independently with the seeded
        RNG, then split 50/50 into CALIBRATION and TEST sets (stratified by
        class — member vs. non-member — to keep both sets balanced).  The
        decision threshold is fit on CALIBRATION labels; advantage/AUC are
        reported on the disjoint TEST set only.

        LABEL-LEAKAGE CONTRACT
        ----------------------
        Per-sample attack statistics are computed by the module-level pure
        functions (_stat_max_confidence, _stat_neg_entropy, _stat_modified_entropy)
        which accept only the probability vector — no membership label is passed
        into the statistic functions.
        """
        rng = np.random.RandomState(seed)

        # ------------------------------------------------------------------
        # HONESTY GATE 1 — minimum sample count
        # ------------------------------------------------------------------
        if (
            len(member_samples) < MIN_REAL_SAMPLES
            or len(non_member_samples) < MIN_REAL_SAMPLES
        ):
            info_result = TestResult(
                test_name="RealInference_Gate",
                success=True,
                attack_succeeded=False,
                metrics={
                    "member_count": len(member_samples),
                    "non_member_count": len(non_member_samples),
                    "min_required": MIN_REAL_SAMPLES,
                },
                duration_seconds=0.0,
                error=(
                    f"Insufficient data: need >= {MIN_REAL_SAMPLES} confirmed members "
                    f"AND >= {MIN_REAL_SAMPLES} confirmed non-members; "
                    f"got {len(member_samples)} members, {len(non_member_samples)} non-members."
                ),
            )
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Membership Inference — Insufficient Data",
                category=AttackCategory.MEMBERSHIP_INFERENCE,
                severity=Severity.INFO,
                description=(
                    "run_real_inference() requires at least "
                    f"{MIN_REAL_SAMPLES} confirmed-member and "
                    f"{MIN_REAL_SAMPLES} confirmed-non-member samples to "
                    "compute a statistically meaningful advantage estimate.  "
                    "No finding was emitted because the honesty gate was not cleared."
                ),
                evidence={
                    "member_count": len(member_samples),
                    "non_member_count": len(non_member_samples),
                    "min_required": MIN_REAL_SAMPLES,
                },
                remediation="Provide more confirmed member/non-member samples.",
            ))
            return [info_result]

        # ------------------------------------------------------------------
        # HONESTY GATE 2 — scope check: target must expose probabilities
        # ------------------------------------------------------------------
        probe = member_samples[0]
        try:
            probe_probs = self.target.get_probabilities(probe)
        except Exception as exc:
            probe_probs = None
            self.logger.warning(f"Probability probe failed: {exc}")

        if probe_probs is None:
            oos_result = TestResult(
                test_name="RealInference_ScopeCheck",
                success=True,
                attack_succeeded=False,
                metrics={"probabilities_available": False},
                duration_seconds=0.0,
                error=(
                    "Target does not expose probability outputs "
                    "(get_probabilities() returned None).  "
                    "This implementation requires a classifier that returns softmax "
                    "probabilities.  LLM text-generation endpoints are out of scope."
                ),
            )
            self.add_finding(Finding(
                id=self.generate_finding_id(),
                title="Membership Inference — Out of Scope (No Probabilities)",
                category=AttackCategory.MEMBERSHIP_INFERENCE,
                severity=Severity.INFO,
                description=(
                    "The target model does not expose class probability outputs.  "
                    "Probability-based membership inference (max-confidence, entropy, "
                    "Mentr) requires softmax/probability outputs from a classifier.  "
                    "LLM endpoints (e.g. LLMInterface.get_probabilities → None) are "
                    "explicitly out of scope for this implementation.  "
                    "No privacy-leakage finding was emitted."
                ),
                evidence={"probabilities_available": False},
                remediation=(
                    "If the target is a classifier, ensure get_probabilities() "
                    "returns a valid probability vector.  For LLM targets, "
                    "membership inference via token probabilities or other methods "
                    "is a separate research problem not covered by this module."
                ),
            ))
            return [oos_result]

        # ------------------------------------------------------------------
        # COLLECT STATISTICS  (label-free — see module docstring)
        # Probe each sample once; store per-variant statistics keyed by
        # original index so the stratified calib/test split is preserved
        # even if some samples fail to return probabilities.
        # ------------------------------------------------------------------
        all_samples = list(member_samples) + list(non_member_samples)
        all_labels  = [1] * len(member_samples) + [0] * len(non_member_samples)

        attack_variants = [
            ("MaxConfidence",   _stat_max_confidence),
            ("NegEntropy",      _stat_neg_entropy),
            ("ModifiedEntropy", _stat_modified_entropy),
        ]

        # stat_matrix[idx][vname] = float statistic for sample at `idx`
        # Only populated for samples where get_probabilities() succeeded.
        stat_matrix: Dict[int, Dict[str, float]] = {}
        queries_used = 0

        for idx, sample in enumerate(all_samples):
            try:
                probs = self.target.get_probabilities(sample)
                if probs is None:
                    continue
                queries_used += 1
                # stat_fn receives ONLY the probability vector — no label
                stat_matrix[idx] = {vname: fn(probs) for vname, fn in attack_variants}
            except Exception as exc:
                self.logger.debug(f"Sample {idx} skipped: {exc}")

        # ------------------------------------------------------------------
        # STRATIFIED 50/50 SPLIT — member and non-member shuffled separately
        # so both calibration and test sets remain balanced.
        # ------------------------------------------------------------------
        mem_idx = [i for i in range(len(member_samples))                         if i in stat_matrix]
        non_idx = [i for i in range(len(member_samples), len(all_samples))       if i in stat_matrix]
        rng.shuffle(mem_idx)
        rng.shuffle(non_idx)

        mid_m = len(mem_idx) // 2
        mid_n = len(non_idx) // 2
        calib_idx = mem_idx[:mid_m] + non_idx[:mid_n]
        test_idx  = mem_idx[mid_m:]  + non_idx[mid_n:]

        # ------------------------------------------------------------------
        # PER-VARIANT EVALUATION
        # ------------------------------------------------------------------
        results = []
        for vname, _ in attack_variants:
            start_time = time.time()

            # Build calib / test stat+label lists for this variant.
            calib_pairs = [(stat_matrix[i][vname], all_labels[i]) for i in calib_idx]
            test_pairs  = [(stat_matrix[i][vname], all_labels[i]) for i in test_idx]

            # Both splits must contain BOTH classes (member AND non-member).
            # A single-class split (e.g. all non-members failed to return
            # probabilities) makes a >= threshold rule trivially "accurate"
            # against one label, which would otherwise manufacture a false
            # advantage with zero real discrimination.  Refuse to score it.
            calib_classes = {l for _, l in calib_pairs}
            test_classes = {l for _, l in test_pairs}
            if (
                len(calib_pairs) < 4
                or len(test_pairs) < 4
                or len(calib_classes) < 2
                or len(test_classes) < 2
            ):
                results.append(TestResult(
                    test_name=f"RealInference_{vname}",
                    success=False,
                    attack_succeeded=False,
                    metrics={
                        "error": "degenerate split",
                        "calib_samples": len(calib_pairs),
                        "test_samples": len(test_pairs),
                        "calib_classes": sorted(calib_classes),
                        "test_classes": sorted(test_classes),
                    },
                    duration_seconds=time.time() - start_time,
                    error=(
                        "Calibration/test split lacks both member and non-member "
                        "classes (too few valid probability responses, or all of "
                        "one class failed to probe). No advantage can be measured."
                    ),
                ))
                continue

            # Fit threshold on CALIBRATION — labels used ONLY here.
            calib_stats_  = [s for s, _ in calib_pairs]
            calib_labels_ = [l for _, l in calib_pairs]
            threshold = self._fit_threshold_on_calibration(calib_stats_, calib_labels_)

            # Score on TEST — labels used ONLY here for scoring.
            test_stats_  = [s for s, _ in test_pairs]
            test_labels_ = [l for _, l in test_pairs]
            accuracy, advantage, auc, tpr_at_fpr = self._score_on_test(
                test_stats_, test_labels_, threshold
            )

            duration = time.time() - start_time

            # Derive severity from measured test-set advantage.
            severity, attack_succeeded = self._advantage_to_severity(advantage)

            metrics = {
                "attack_accuracy":  accuracy,
                "advantage":        advantage,
                "auc":              auc,
                "tpr_at_10pct_fpr": tpr_at_fpr,
                "fitted_threshold": threshold,
                "calib_samples":    len(calib_pairs),
                "test_samples":     len(test_pairs),
                "data_source":      "caller_supplied_real",
            }

            if severity != Severity.INFO:
                evidence = dict(metrics)
                evidence["variant"] = vname
                self.add_finding(Finding(
                    id=self.generate_finding_id(),
                    title=f"Membership Inference Vulnerability ({vname})",
                    category=AttackCategory.MEMBERSHIP_INFERENCE,
                    severity=severity,
                    description=(
                        f"Membership inference attack ({vname}) achieved "
                        f"{accuracy*100:.1f}% balanced accuracy on the held-out "
                        f"test split (advantage: {advantage*100:.1f}%).  "
                        f"AUC: {auc:.3f}.  TPR@10%FPR: {tpr_at_fpr*100:.1f}%.  "
                        f"Threshold fitted on a disjoint calibration set; "
                        f"test-set labels were NEVER used to fit the threshold.  "
                        f"Data: {len(calib_pairs)} calib + {len(test_pairs)} test "
                        f"samples from caller-supplied confirmed member/non-member sets."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Apply differential privacy (DP-SGD) during training, "
                        "confidence score perturbation / temperature scaling, "
                        "or strong L2/dropout regularization to reduce overfitting."
                    ),
                ))

            results.append(TestResult(
                test_name=f"RealInference_{vname}",
                success=True,
                attack_succeeded=attack_succeeded,
                metrics=metrics,
                duration_seconds=duration,
                queries_used=queries_used,
            ))

        return results

    # ------------------------------------------------------------------
    # Real-inference helpers
    # ------------------------------------------------------------------

    def _fit_threshold_on_calibration(
        self,
        calib_stats: List[float],
        calib_labels: List[int],
    ) -> float:
        """Fit the optimal decision threshold on the CALIBRATION split only.

        Labels (calib_labels) are used ONLY here — to pick the threshold that
        maximises balanced accuracy on calibration.  The threshold is then
        applied to the test set WITHOUT further tuning.

        The statistic is oriented so that higher = more member-like, so the
        decision rule is always: predicted_member = (stat >= threshold).

        The threshold maximises BALANCED accuracy (mean of member-recall and
        non-member-recall), not plain accuracy, so an imbalanced calibration
        set cannot be won by a degenerate majority-class predictor.
        """
        if not calib_stats:
            return 0.5
        # Candidate thresholds: every observed statistic value + percentile grid.
        candidates = list(set(calib_stats))
        # Add a fine percentile grid to avoid missing the optimum.
        candidates += list(np.percentile(calib_stats, range(0, 101, 5)))
        best_acc = -1.0
        best_thr = float(np.median(calib_stats))
        for thr in candidates:
            preds = [1 if s >= thr else 0 for s in calib_stats]
            acc = self._balanced_accuracy(preds, calib_labels)
            if acc > best_acc:
                best_acc = acc
                best_thr = thr
        return best_thr

    @staticmethod
    def _balanced_accuracy(preds: List[int], labels: List[int]) -> float:
        """Balanced accuracy = mean(member-recall TPR, non-member-recall TNR).

        Immune to class imbalance: a predictor that calls everything a member
        scores TPR=1, TNR=0 -> 0.5 (no advantage), unlike plain accuracy which
        would inflate to the member fraction.  Assumes BOTH classes are present
        (the caller guarantees this via the degenerate-split guard).
        """
        tp = sum(1 for p, l in zip(preds, labels) if l == 1 and p == 1)
        fn = sum(1 for p, l in zip(preds, labels) if l == 1 and p == 0)
        tn = sum(1 for p, l in zip(preds, labels) if l == 0 and p == 0)
        fp = sum(1 for p, l in zip(preds, labels) if l == 0 and p == 1)
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        tnr = tn / (tn + fp) if (tn + fp) else 0.0
        return 0.5 * (tpr + tnr)

    def _score_on_test(
        self,
        test_stats: List[float],
        test_labels: List[int],
        threshold: float,
    ) -> Tuple[float, float, float, float]:
        """Score attack accuracy, advantage, AUC, and TPR@10%FPR on the TEST split.

        Labels are used here ONLY for scoring — the threshold is already fixed.

        ``accuracy`` is BALANCED accuracy (mean of member/non-member recall), so
        advantage stays honest under class imbalance — a degenerate single-class
        predictor scores 0.5 (advantage 0), never an inflated value.

        Returns
        -------
        (balanced_accuracy, advantage, auc, tpr_at_10pct_fpr)
        """
        preds = [1 if s >= threshold else 0 for s in test_stats]
        accuracy = self._balanced_accuracy(preds, test_labels)
        advantage = accuracy - 0.5

        auc = self._calculate_auc(test_stats, test_labels)

        # TPR@10% FPR — more practical than 0.1% FPR for small test sets.
        non_member_stats = [s for s, l in zip(test_stats, test_labels) if l == 0]
        member_stats     = [s for s, l in zip(test_stats, test_labels) if l == 1]
        if non_member_stats and member_stats:
            fpr_thr = np.percentile(non_member_stats, 90)  # top 10% of non-members
            tpr_at_fpr = sum(1 for s in member_stats if s >= fpr_thr) / len(member_stats)
        else:
            tpr_at_fpr = 0.0

        return float(accuracy), float(advantage), float(auc), float(tpr_at_fpr)

    def _advantage_to_severity(self, advantage: float) -> Tuple[Severity, bool]:
        """Map measured advantage (accuracy - 0.5) to Severity and attack_succeeded.

        Thresholds are documented in the module docstring.  Only a non-INFO
        severity sets attack_succeeded=True (reflecting a real, measured leak).
        """
        if advantage >= _ADV_HIGH:
            return Severity.HIGH, True
        if advantage >= _ADV_MEDIUM:
            return Severity.MEDIUM, True
        if advantage >= _ADV_LOW:
            return Severity.LOW, True
        return Severity.INFO, False

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
