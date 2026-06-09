#!/usr/bin/env python3
"""
Unit tests for the real-measurement path of MembershipInferenceModule.

Phase 7 — run_real_inference() tests.

Tests:
  1. overfit_target  — sharply-peaked probs for known members → HIGH/MEDIUM finding,
                        measured advantage clearly > 0.25 on test split.
  2. generalized_target — statistically identical probs for members/non-members →
                           NO non-INFO finding, advantage near 0 (|adv| < 0.15).
  3. honesty_gate       — empty / too-small sample sets → NO non-INFO finding.
  4. label_leakage_guard — statistic functions accept only model output (no label).

All targets are built inline — no shared conftest mocks are reused here.
Everything is seeded via seed= param or local np.random.RandomState; global
numpy state is never mutated.
"""

import sys
from pathlib import Path
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.base import (
    ModelInterface, Severity, AttackCategory,
)
from scripts.inference.membership_inference import (
    MembershipInferenceModule,
    MIN_REAL_SAMPLES,
    _stat_max_confidence,
    _stat_neg_entropy,
    _stat_modified_entropy,
)


# ---------------------------------------------------------------------------
# In-test target stubs — built from scratch, no conftest dependency
# ---------------------------------------------------------------------------

class _OverfitTarget(ModelInterface):
    """Classifier-like target that memorises a set of member inputs.

    For member inputs: returns a sharply-peaked probability vector (low entropy,
    high max-confidence) — simulating a model that has overfit to training data.
    For non-member inputs: returns a flat/uniform probability vector (high
    entropy) — simulating an unseen example.

    "Memory" is keyed on a round-trip through list→tuple so any list input can
    be matched.  The caller must register member inputs via the constructor.
    """

    def __init__(self, member_samples, num_classes: int = 10, seed: int = 0):
        rng = np.random.RandomState(seed)
        # Store each member as a hashable key.
        self._member_keys = set()
        for s in member_samples:
            self._member_keys.add(self._key(s))
        self._num_classes = num_classes
        self._rng = rng

    @staticmethod
    def _key(sample):
        """Convert a sample to a hashable key (rounds floats to 4 dp)."""
        if isinstance(sample, np.ndarray):
            return tuple(np.round(sample.ravel(), 4).tolist())
        if isinstance(sample, list):
            flat = []
            for v in sample:
                if isinstance(v, list):
                    flat.extend(v)
                else:
                    flat.append(v)
            return tuple(round(float(v), 4) for v in flat)
        return (round(float(sample), 4),)

    def _is_member(self, sample) -> bool:
        return self._key(sample) in self._member_keys

    def get_probabilities(self, sample):
        k = self._num_classes
        if self._is_member(sample):
            # Peaked: class 0 gets 0.92, rest share 0.08 uniformly.
            probs = [0.08 / (k - 1)] * k
            probs[0] = 0.92
        else:
            # Flat: uniform — no signal.
            probs = [1.0 / k] * k
        return probs

    def predict(self, sample):
        probs = self.get_probabilities(sample)
        return {"class": int(np.argmax(probs)), "probabilities": probs}

    def get_logits(self, sample):
        probs = self.get_probabilities(sample)
        return [float(np.log(p + 1e-12)) for p in probs]


class _GeneralizedTarget(ModelInterface):
    """Classifier-like target that returns a FIXED, CONSTANT probability
    distribution for every input — no membership leakage by construction.

    Every call returns the same vector regardless of input, so the
    per-sample statistic (max-conf, neg-entropy, Mentr) is bit-identical
    across every sample in both calibration and test.  That collapses the
    threshold search to a single candidate, making advantage deterministically
    0.0 and AUC 0.5 for every variant and every PYTHONHASHSEED.

    Using hash(str(sample)) to vary the peak position would be WRONG here:
    Python's str hash is PYTHONHASHSEED-salted, causing the 'threshold on
    calibration' search to overfit ~0.08 spurious advantage, which drifts
    across processes and makes the |advantage|<0.15 band unreliable.
    """

    def __init__(self, num_classes: int = 10):
        self._num_classes = num_classes
        # Fixed distribution: class 0 always gets 0.55, rest uniform.
        k = num_classes
        self._probs = [0.05] * k
        self._probs[0] = 0.55

    def get_probabilities(self, sample):
        return list(self._probs)  # return a copy; same value every call

    def predict(self, sample):
        return {"class": 0, "probabilities": self.get_probabilities(sample)}

    def get_logits(self, sample):
        return [float(np.log(p + 1e-12)) for p in self._probs]


class _NoProbsTarget(ModelInterface):
    """Target that returns None for get_probabilities (simulates LLM endpoint)."""

    def predict(self, sample):
        return "some text"

    def get_probabilities(self, sample):
        return None

    def get_logits(self, sample):
        return None


# ---------------------------------------------------------------------------
# Helper: generate a deterministic list of simple float-list samples.
# ---------------------------------------------------------------------------

def _make_samples(n: int, seed: int) -> list:
    rng = np.random.RandomState(seed)
    return [rng.rand(4).tolist() for _ in range(n)]


# ---------------------------------------------------------------------------
# 1. Overfit target — high advantage, non-INFO finding
# ---------------------------------------------------------------------------

class TestOverfitTarget:
    """On an overfit target the attack should detect the membership leakage."""

    SEED = 1234
    N = 120  # generous sample count for each class (60 calib + 60 test)

    @pytest.fixture
    def member_samples(self):
        return _make_samples(self.N, seed=10)

    @pytest.fixture
    def non_member_samples(self):
        return _make_samples(self.N, seed=20)

    @pytest.fixture
    def module(self, member_samples, tmp_path):
        target = _OverfitTarget(member_samples=member_samples, num_classes=10, seed=0)
        return MembershipInferenceModule(
            target=target,
            output_dir=tmp_path,
            config={},
        )

    def test_advantage_exceeds_threshold(self, module, member_samples, non_member_samples):
        """Advantage on the held-out test set must clear 0.25 for the overfit target."""
        results = module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        assert len(results) > 0, "run_real_inference returned no results"
        adv_values = [r.metrics.get("advantage", 0.0) for r in results if r.success]
        assert adv_values, "No successful variant results"
        max_adv = max(adv_values)
        assert max_adv > 0.25, (
            f"Expected advantage > 0.25 on overfit target; got max={max_adv:.4f}.  "
            f"Per-variant: {dict(zip([r.test_name for r in results], adv_values))}"
        )

    def test_non_info_finding_emitted(self, module, member_samples, non_member_samples):
        """At least one HIGH/MEDIUM/LOW finding must be emitted on overfit target."""
        module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        non_info = [
            f for f in module.findings
            if f.severity != Severity.INFO
        ]
        assert len(non_info) > 0, (
            "Expected at least one non-INFO finding on overfit target; "
            f"findings: {[(f.severity, f.title) for f in module.findings]}"
        )

    def test_attack_succeeded_true_on_real_leak(self, module, member_samples, non_member_samples):
        """attack_succeeded must be True for variants that detect a real leak."""
        results = module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        succeeded = [r for r in results if r.attack_succeeded]
        assert len(succeeded) > 0, (
            "Expected attack_succeeded=True for at least one variant on overfit target"
        )

    def test_data_source_is_real(self, module, member_samples, non_member_samples):
        """Metrics must record data_source='caller_supplied_real'."""
        results = module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        for r in results:
            if r.success:
                assert r.metrics.get("data_source") == "caller_supplied_real", (
                    f"{r.test_name} has wrong data_source: {r.metrics.get('data_source')}"
                )


# ---------------------------------------------------------------------------
# 2. Generalized target — near-zero advantage, INFO-only findings
# ---------------------------------------------------------------------------

class TestGeneralizedTarget:
    """On a generalized target the attack should find no meaningful leakage."""

    SEED = 5678
    N = 120

    @pytest.fixture
    def member_samples(self):
        return _make_samples(self.N, seed=30)

    @pytest.fixture
    def non_member_samples(self):
        return _make_samples(self.N, seed=40)

    @pytest.fixture
    def module(self, tmp_path):
        target = _GeneralizedTarget(num_classes=10)
        return MembershipInferenceModule(
            target=target,
            output_dir=tmp_path,
            config={},
        )

    def test_advantage_near_zero(self, module, member_samples, non_member_samples):
        """All variant advantages must be within ±0.15 of zero (no leakage)."""
        results = module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        assert len(results) > 0
        for r in results:
            if r.success:
                adv = r.metrics.get("advantage", 0.0)
                assert abs(adv) < 0.15, (
                    f"{r.test_name}: expected |advantage| < 0.15 on generalized "
                    f"target; got advantage={adv:.4f}"
                )

    def test_no_non_info_finding(self, module, member_samples, non_member_samples):
        """No HIGH/MEDIUM/LOW finding must be emitted on a generalized target."""
        module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        non_info = [
            f for f in module.findings
            if f.severity != Severity.INFO
        ]
        assert len(non_info) == 0, (
            f"Unexpected non-INFO findings on generalized target: "
            f"{[(f.severity, f.title, f.evidence.get('advantage')) for f in non_info]}"
        )

    def test_attack_succeeded_false(self, module, member_samples, non_member_samples):
        """attack_succeeded must be False for all variants on a generalized target."""
        results = module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        for r in results:
            assert r.attack_succeeded is False, (
                f"{r.test_name}: expected attack_succeeded=False on generalized "
                f"target (advantage={r.metrics.get('advantage')})"
            )


# ---------------------------------------------------------------------------
# 3. Contrast assertion — overfit advantage >> generalized advantage
# ---------------------------------------------------------------------------

class TestContrastOverfitVsGeneralized:
    """The core assertion: overfit advantage must exceed generalized advantage
    by a clear margin, proving the numbers track reality."""

    SEED = 9999
    N = 120

    def _run(self, target, member_samples, non_member_samples, tmp_path):
        module = MembershipInferenceModule(
            target=target, output_dir=tmp_path, config={}
        )
        results = module.run_real_inference(
            member_samples=member_samples,
            non_member_samples=non_member_samples,
            seed=self.SEED,
        )
        advantages = [
            r.metrics.get("advantage", 0.0)
            for r in results if r.success
        ]
        return max(advantages) if advantages else 0.0

    def test_overfit_advantage_exceeds_generalized_by_margin(self, tmp_path):
        """max_advantage(overfit) − max_advantage(generalized) must be >= 0.25."""
        member_samples     = _make_samples(self.N, seed=50)
        non_member_samples = _make_samples(self.N, seed=60)

        overfit_target     = _OverfitTarget(member_samples=member_samples, seed=0)
        generalized_target = _GeneralizedTarget()

        # tmp_path gives us two subdirs
        adv_overfit = self._run(
            overfit_target, member_samples, non_member_samples,
            tmp_path / "overfit"
        )
        adv_gen = self._run(
            generalized_target, member_samples, non_member_samples,
            tmp_path / "gen"
        )

        margin = adv_overfit - adv_gen
        assert margin >= 0.25, (
            f"Expected overfit advantage to exceed generalized by >= 0.25; "
            f"overfit={adv_overfit:.4f}, generalized={adv_gen:.4f}, margin={margin:.4f}"
        )


# ---------------------------------------------------------------------------
# 4. Honesty gate — empty / too-small sets → no non-INFO finding
# ---------------------------------------------------------------------------

class TestHonestyGate:
    """Structural gate: must never emit a non-INFO finding without real data."""

    @pytest.fixture
    def module(self, tmp_path):
        target = _OverfitTarget(member_samples=[], num_classes=10)
        return MembershipInferenceModule(
            target=target, output_dir=tmp_path, config={}
        )

    def test_empty_member_set_no_non_info(self, module):
        results = module.run_real_inference(
            member_samples=[],
            non_member_samples=_make_samples(50, seed=1),
        )
        assert len(results) == 1
        assert results[0].test_name == "RealInference_Gate"
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert len(non_info) == 0, f"Unexpected findings: {non_info}"

    def test_empty_non_member_set_no_non_info(self, module):
        results = module.run_real_inference(
            member_samples=_make_samples(50, seed=1),
            non_member_samples=[],
        )
        assert len(results) == 1
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert len(non_info) == 0

    def test_too_few_members_no_non_info(self, module):
        """Below MIN_REAL_SAMPLES (19 < 20) → gate triggers."""
        results = module.run_real_inference(
            member_samples=_make_samples(MIN_REAL_SAMPLES - 1, seed=2),
            non_member_samples=_make_samples(50, seed=3),
        )
        assert len(results) == 1
        assert results[0].test_name == "RealInference_Gate"
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert len(non_info) == 0

    def test_too_few_non_members_no_non_info(self, module):
        """Below MIN_REAL_SAMPLES (19 < 20) → gate triggers."""
        results = module.run_real_inference(
            member_samples=_make_samples(50, seed=4),
            non_member_samples=_make_samples(MIN_REAL_SAMPLES - 1, seed=5),
        )
        assert len(results) == 1
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert len(non_info) == 0

    def test_exactly_min_samples_passes_gate(self, tmp_path):
        """Exactly MIN_REAL_SAMPLES each → gate passes (result list has >1 entry)."""
        members     = _make_samples(MIN_REAL_SAMPLES, seed=10)
        non_members = _make_samples(MIN_REAL_SAMPLES, seed=11)
        target = _OverfitTarget(member_samples=members, num_classes=10)
        module = MembershipInferenceModule(
            target=target, output_dir=tmp_path, config={}
        )
        results = module.run_real_inference(
            member_samples=members,
            non_member_samples=non_members,
            seed=0,
        )
        # Gate result has test_name "RealInference_Gate"; if gate passes we
        # get per-variant results instead.
        names = [r.test_name for r in results]
        assert "RealInference_Gate" not in names, (
            f"Gate triggered at exactly MIN_REAL_SAMPLES={MIN_REAL_SAMPLES} — "
            "should pass: results={names}"
        )


# ---------------------------------------------------------------------------
# 5. LLM / no-probabilities scope gate
# ---------------------------------------------------------------------------

class TestNoProbsGate:
    """Targets with no probability output → INFO only, out-of-scope message."""

    def test_no_probs_target_info_only(self, tmp_path):
        target = _NoProbsTarget()
        module = MembershipInferenceModule(
            target=target, output_dir=tmp_path, config={}
        )
        results = module.run_real_inference(
            member_samples=_make_samples(50, seed=7),
            non_member_samples=_make_samples(50, seed=8),
        )
        assert len(results) == 1
        assert results[0].test_name == "RealInference_ScopeCheck"
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert len(non_info) == 0

    def test_no_probs_finding_mentions_scope(self, tmp_path):
        target = _NoProbsTarget()
        module = MembershipInferenceModule(
            target=target, output_dir=tmp_path, config={}
        )
        module.run_real_inference(
            member_samples=_make_samples(50, seed=9),
            non_member_samples=_make_samples(50, seed=10),
        )
        assert len(module.findings) == 1
        desc = module.findings[0].description.lower()
        assert "out of scope" in desc or "llm" in desc or "probability" in desc, (
            f"Finding description doesn't mention scope/LLM/probability: {desc}"
        )


# ---------------------------------------------------------------------------
# 6. Label-leakage guard — statistic functions are label-free pure functions
# ---------------------------------------------------------------------------

class TestLabelLeakageGuard:
    """Assert that the per-sample statistic functions are pure:
    they accept ONLY model output (probabilities) and return the same value
    regardless of what membership label you would assign.
    This is the structural proof of the label-leakage contract."""

    PROBS = [0.1, 0.6, 0.1, 0.1, 0.1]  # a fixed probability vector

    def test_max_confidence_takes_no_label(self):
        """_stat_max_confidence must accept only probs, not a label argument."""
        import inspect
        sig = inspect.signature(_stat_max_confidence)
        params = list(sig.parameters.keys())
        assert params == ["probs"], (
            f"_stat_max_confidence signature must be (probs); got {params}"
        )

    def test_neg_entropy_takes_no_label(self):
        import inspect
        sig = inspect.signature(_stat_neg_entropy)
        params = list(sig.parameters.keys())
        assert params == ["probs"], (
            f"_stat_neg_entropy signature must be (probs); got {params}"
        )

    def test_modified_entropy_takes_no_label(self):
        import inspect
        sig = inspect.signature(_stat_modified_entropy)
        params = list(sig.parameters.keys())
        assert params == ["probs"], (
            f"_stat_modified_entropy signature must be (probs); got {params}"
        )

    def test_stat_values_identical_regardless_of_hypothetical_label(self):
        """Calling the statistic with the same probs must give the same result
        whether we would label that sample as member (1) or non-member (0).
        Since labels are not parameters, this is trivially true — but we
        verify the return values are deterministic and label-independent."""
        probs = self.PROBS
        # Call each function twice with the same probs — results must be equal.
        for fn in [_stat_max_confidence, _stat_neg_entropy, _stat_modified_entropy]:
            v1 = fn(probs)
            v2 = fn(probs)
            assert v1 == v2, f"{fn.__name__} is not deterministic: {v1} != {v2}"

    def test_max_confidence_correct_value(self):
        v = _stat_max_confidence(self.PROBS)
        assert abs(v - 0.6) < 1e-9, f"Expected 0.6, got {v}"

    def test_neg_entropy_higher_for_peaked_than_uniform(self):
        """Peaked distribution must have a HIGHER neg-entropy than uniform.
        (Peaked = lower entropy → neg-entropy = less negative = higher value.)"""
        uniform = [0.2, 0.2, 0.2, 0.2, 0.2]
        peaked  = [0.01, 0.96, 0.01, 0.01, 0.01]
        assert _stat_neg_entropy(peaked) > _stat_neg_entropy(uniform), (
            "Peaked distribution should have higher neg-entropy than uniform"
        )

    def test_max_confidence_higher_for_peaked_than_uniform(self):
        uniform = [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1]
        peaked  = [0.01] * 9 + [0.91]
        assert _stat_max_confidence(peaked) > _stat_max_confidence(uniform)


# ---------------------------------------------------------------------------
# 7. Determinism — same seed → same results
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Same seed must produce identical results on successive calls."""

    SEED = 42
    N = 60

    def test_same_seed_same_advantage(self, tmp_path):
        members     = _make_samples(self.N, seed=70)
        non_members = _make_samples(self.N, seed=80)
        target = _OverfitTarget(member_samples=members, num_classes=10)

        def run():
            module = MembershipInferenceModule(
                target=target,
                output_dir=tmp_path / f"det_{id(object())}",
                config={},
            )
            results = module.run_real_inference(
                member_samples=members,
                non_member_samples=non_members,
                seed=self.SEED,
            )
            return {r.test_name: r.metrics.get("advantage") for r in results if r.success}

        adv1 = run()
        adv2 = run()
        assert adv1 == adv2, (
            f"Seeded runs gave different advantages: {adv1} vs {adv2}"
        )


# ---------------------------------------------------------------------------
# 8. R2b regression guard — run_tests() quarantine must not regress
# ---------------------------------------------------------------------------

class TestR2bRegressionGuard:
    """Verify the synthetic run_tests() quarantine is intact (R2b regression guard).
    These duplicate the assertions in test_r2_r2b_r9_r11.py to catch any
    accidental regression introduced by Phase 7 edits."""

    def _module(self, tmp_path, config=None):
        from tests.conftest import MockModelInterface
        target = MockModelInterface(num_classes=10, vulnerable=False)
        cfg = dict(config or {})
        # Use a tiny input_shape so the scaffold test methods run fast; the
        # default (3,224,224) makes test_label_only_attack very slow at 100
        # samples × 11 predict calls — a pre-existing issue not introduced here.
        cfg.setdefault("input_shape", (3, 4, 4))
        cfg.setdefault("num_classes", 10)
        return MembershipInferenceModule(
            target=target,
            output_dir=tmp_path,
            config=cfg,
        )

    def test_default_run_tests_returns_empty(self, tmp_path):
        """Default config → run_tests() returns [] and emits no findings."""
        mod = self._module(tmp_path)
        results = mod.run_tests()
        assert results == [], f"Expected [], got {results}"
        assert mod.findings == [], f"Expected no findings, got {mod.findings}"

    def test_allow_synthetic_runs_four_methods(self, tmp_path):
        """allow_synthetic=True → exactly 4 scaffold results (tiny input_shape)."""
        mod = self._module(tmp_path, config={"allow_synthetic": True})
        results = mod.run_tests()
        assert len(results) == 4, f"Expected 4, got {len(results)}"

    def test_allow_synthetic_findings_are_info_only(self, tmp_path):
        """Synthetic path must emit only INFO findings (no severity escalation)."""
        mod = self._module(tmp_path, config={"allow_synthetic": True})
        mod.run_tests()
        for f in mod.findings:
            assert f.severity == Severity.INFO, (
                f"Synthetic path emitted {f.severity} finding: {f.title}"
            )

    def test_individual_test_methods_still_callable(self, tmp_path):
        """test_entropy_attack() must still be directly callable (not gated)."""
        mod = self._module(tmp_path)
        result = mod.test_entropy_attack()
        assert result.test_name == "EntropyAttack"


# ---------------------------------------------------------------------------
# Class-imbalance & degenerate-split honesty (regression for the independent
# review BLOCK): plain accuracy under imbalance, and single-class test splits,
# must NOT manufacture advantage when there is zero real discrimination.
# ---------------------------------------------------------------------------

class _ConstProbsTarget(ModelInterface):
    """Returns an identical probability vector for every input — zero signal.

    A correct attack must report advantage ~0 (INFO) regardless of how many
    members vs non-members are supplied; a plain-accuracy attack would inflate
    to the member fraction under imbalance.
    """

    def __init__(self, num_classes: int = 4):
        k = num_classes
        self._probs = [0.1] * k
        self._probs[0] = 0.7

    def get_probabilities(self, sample):
        return list(self._probs)

    def predict(self, sample):
        return {"class": 0, "probabilities": list(self._probs)}

    def get_logits(self, sample):
        return None


class _LeakyMembersProbeFailNonMembers(ModelInterface):
    """Members get peaked probs; non-members fail the probe (return None).

    This induces a single-class test split (only members survive probing),
    which must be REFUSED — not scored as a perfect attack.
    """

    def __init__(self, member_samples):
        self._mem = {repr(s) for s in member_samples}

    def get_probabilities(self, sample):
        if repr(sample) in self._mem:
            return [0.95, 0.02, 0.02, 0.01]
        return None

    def predict(self, sample):
        return {"class": 0}

    def get_logits(self, sample):
        return None


class TestClassImbalanceHonesty:
    """Regression: imbalance / degenerate splits must not fabricate advantage."""

    def test_imbalanced_zero_signal_no_non_info(self, tmp_path):
        """120 members vs 24 non-members on a zero-signal target → no finding.

        Plain accuracy would report ~0.333 advantage (HIGH) here; balanced
        accuracy must report ~0 (INFO) and emit no HIGH/MEDIUM/LOW finding.
        """
        members = _make_samples(120, seed=101)
        non_members = _make_samples(24, seed=202)
        module = MembershipInferenceModule(
            target=_ConstProbsTarget(), output_dir=tmp_path, config={}
        )
        results = module.run_real_inference(members, non_members, seed=777)

        for r in results:
            adv = r.metrics.get("advantage")
            if adv is not None:
                assert abs(adv) < 0.10, (
                    f"{r.test_name}: zero-signal imbalanced target must yield "
                    f"~0 advantage, got {adv:.4f}"
                )
            assert r.attack_succeeded is False
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert not non_info, (
            f"No non-INFO finding may be emitted for a zero-signal target; "
            f"got {[f.severity.value for f in non_info]}"
        )

    def test_single_class_test_split_refused(self, tmp_path):
        """All non-members fail to probe → degenerate split must be refused."""
        members = _make_samples(60, seed=303)
        non_members = _make_samples(60, seed=404)
        module = MembershipInferenceModule(
            target=_LeakyMembersProbeFailNonMembers(members),
            output_dir=tmp_path,
            config={},
        )
        results = module.run_real_inference(members, non_members, seed=777)

        # Every variant must be a refused (success=False) degenerate split,
        # never a scored advantage.
        for r in results:
            assert r.success is False, (
                f"{r.test_name}: single-class test split must be refused, "
                f"not scored (got metrics={r.metrics})"
            )
            assert r.attack_succeeded is False
        non_info = [f for f in module.findings if f.severity != Severity.INFO]
        assert not non_info, (
            "A single-class split must not emit any non-INFO finding; got "
            f"{[f.severity.value for f in non_info]}"
        )

    def test_balanced_accuracy_helper_imbalance_immune(self):
        """_balanced_accuracy: an all-member predictor scores 0.5 under imbalance."""
        # 100 members, 10 non-members; predict everything member.
        preds = [1] * 110
        labels = [1] * 100 + [0] * 10
        ba = MembershipInferenceModule._balanced_accuracy(preds, labels)
        assert abs(ba - 0.5) < 1e-9, (
            f"All-member predictor must score balanced accuracy 0.5, got {ba}"
        )
