# 0xPR0MPT — Independent Codex Review

**Date:** 08 JUN 2026
**Tool:** `codex exec` (`codex-cli 0.133.0`), sandbox `read-only`, local environment
**Target:** working tree at `13876bc` (current `main` HEAD)
**Inputs:** carry-forward set from `docs/REVIEW-TRIAGE-08JUN2026.md` (Review-1 open +
reframe-closed findings, plus all Review-2 / appendix findings)
**Note:** This is the genuine independent third-tool pass the appendix
(`docs/CODE-REVIEW-APPENDIX.md`) could not run — its remote environment blocked
egress to `api.openai.com`. Codex runs locally here. Prompt archived at
`tmp/codex-review-prompt-08JUN2026.md`; raw verdict at `tmp/codex-verdict-08JUN2026.txt`.

---

## Overall verdict

> Stable `corpus` is still blocked by an import-time numpy dependency under the
> documented minimal install; most experimental findings are now labeled, but
> evasion and summary rollups still overstate scaffolded results.

---

## Verification of carried findings

| ID | Status | Codex severity | File:line | Evidence |
|----|--------|---------------|-----------|----------|
| H-4 | CONFIRMED | LOW | `aiml_pentest.py:97,104,210,449` | CLI only selects/registers `prompt_injection/evasion/extraction/poisoning`; `scripts/inference/*` and `scripts/agent_attacks/*` unreachable. |
| H-5 | CONFIRMED | **HIGH** | `requirements.txt:5,11`, `aiml_pentest.py:45` | Minimal corpus docs say `requests` only, but import-time `EvasionAttackModule` imports numpy; missing numpy crashes before `corpus` runs. |
| M-6 | CONFIRMED | LOW | `scripts/utils/base.py:139` | `APIModelInterface.predict()` always posts `json={"input": ...}`, no configurable schema. |
| M-16 | CONFIRMED | MEDIUM | `scanner.py:364,386,726` | Pickle/model analysis is byte regex over full file; TODOs to replace with `pickletools.genops`. |
| M-23 | CONFIRMED | MEDIUM | `LICENSE.md:1,28` | Software under CC-BY-NC-SA 4.0 with noncommercial restriction. |
| L-16 | PARTIAL | LOW | `tests/unit/test_corpus_generator.py:23` | Fixture is module-scoped (not per-test) but still runs full `generate_all()` once. Timing not verifiable in sandbox. |
| L-17 | CONFIRMED | LOW | `docs/pcev/PLAN-16FEB2026.md:1` | `docs/pcev/` planning artifacts shipped. |
| H-3 | PARTIAL | LOW | `extractor.py:157,174`, `aiml_pentest.py:229` | Finding is INFO and says no surrogate trained — **but `attack_succeeded=True` still feeds "Successful Attacks" rollups.** |
| H-10 | PARTIAL | LOW | `membership_inference.py:169,177`, `aiml_pentest.py:229` | Finding says synthetic labels/not real — **but success still counts as a successful attack.** |
| M-13 | PARTIAL | LOW | `extractor.py:267,270,530` | INFO + disclaims random perturbation — but test name still `JacobianAugmentation` and `attack_succeeded` can be true. |
| H-13 | CONFIRMED | MEDIUM | `evasion_attacks.py:119,156,161` | FGSM uses finite-difference/random approximation but still emits `Severity.HIGH`, unlike downgraded extraction/inference findings. |
| A1 | CONFIRMED | LOW | `aiml_pentest.py:517` | Missing `--config` hits `cfg_path.stat()` before existence check → raw `FileNotFoundError`. |
| A2 | CONFIRMED | LOW | `dashboard/app.py:361` | `/api/corpus/regenerate` lacks `Depends(_require_xhr)`, unlike its siblings. |
| A3 | CONFIRMED | **MEDIUM** (appendix said LOW) | `dashboard/app.py:60,136,343` | Targeted corpus is module-global `_last_generated_corpus`, shared across clients and workers. |
| A4 | CONFIRMED | **MEDIUM** (appendix said LOW) | `scanner.py:682,685,694` | `<` branch catches `<=` first → `<=1.0` compares against `=1.0`; comparison errors return affected/true. |
| A5 | CONFIRMED | **MEDIUM** (appendix said LOW) | `scanner.py:386,445,590,720` | Unbounded `f.read()`; per-file failures suppressed at debug level. |

**Key cross-review insight:** the "downgrade-to-INFO + disclaimer" closure of
H-3 / H-10 / M-13 is **leaky**. The finding *text* is honest, but the underlying
`TestResult` still carries `attack_succeeded=True`, which the orchestrator's
summary (`aiml_pentest.py:229`) tallies into "Successful Attacks." An operator
reading the run summary — not each finding's prose — still sees fabricated
successes. Disclaimer-based closure is therefore **not fully adequate** until the
`attack_succeeded` flag / rollup is also corrected.

---

## NEW findings (not in either prior review)

### N-1 [MEDIUM] — Evasion reframe only covered FGSM; PGD/boundary/hopskipjump still emit CRITICAL/HIGH
`evasion_attacks.py:258,263,392,397,530,535` emit CRITICAL/HIGH findings from
scaffolded random/generated-sample attacks. The remediation that relabelled FGSM
(H-13) was never applied to the sibling evasion attacks, so the same
non-measurement-grade class still produces top-severity findings.
**Fix direction:** downgrade experimental evasion findings to INFO and apply the
same "research scaffold, not measured" wording to each emitted finding *and* its
result metric.

### N-2 [LOW] — Dashboard generation accepts `count` but ignores it
`dashboard/app.py:76,78,327,349` — `GenerateRequest.count` is defined, then the
endpoint generates all cases and returns the full `len(all_cases)`. The API/UI
contract is misleading.
**Fix direction:** implement bounded sampling after category filtering, or remove
`count` from the API/UI contract.

---

## Fix first (codex recommendation)

> Fix **H-5** first: move experimental attack imports behind the `scan` path or
> lazy-load modules in `_get_module()`. The documented stable `corpus` workflow
> can fail at import before argparse runs.

---

## Severity reconciliation vs. prior reviews

- Codex **escalated** A3/A4/A5 from the appendix's LOW to MEDIUM (cross-client
  state bleed; silent CVE-matcher false positives; scanner OOM/incomplete scan).
- Codex **rated H-5 HIGH** — agreeing with this triage that it is a concrete,
  reproducible stable-surface regression, not a documentation nicety. This is the
  single point where the appendix's APPROVE-WITH-CHANGES verdict is most
  optimistic: it scoped to the stable surface but did not catch that the stable
  surface itself import-crashes under the documented minimal install.
- Codex **confirmed H-4 as LOW** (not the HIGH of Review 1) — reasonable given the
  reframe to corpus-first, but the modules are still dead code.
- Net new exposure beyond both prior reviews: the leaky `attack_succeeded` rollup
  (partial reopen of H-3/H-10/M-13) and **N-1** (un-reframed evasion attacks).
