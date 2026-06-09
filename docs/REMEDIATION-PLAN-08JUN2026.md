# 0xPR0MPT — Consolidated Remediation Plan

**Date:** 08 JUN 2026
**Gate status:** Independent Codex full-HEAD review returned **VERDICT: BLOCK**
(driver: minimal-install import crash). This plan clears that gate and closes the
residual items from all three review sources.

**Sources consolidated (deduplicated):**
- `docs/APP-REVIEW-FINDINGS-11MAY2026.md` — still-open items (see `docs/REVIEW-TRIAGE-08JUN2026.md`).
- `docs/CODE-REVIEW-APPENDIX.md` (branch `claude/full-code-review-vapgjn`) — appendix A1–A5.
- `docs/CODEX-REVIEW-08JUN2026.md` — carry-forward codex pass (leaky rollup, N-1, N-2).
- `docs/CODEX-REVIEW-FULLHEAD-08JUN2026.md` — full-HEAD codex pass, **BLOCK**.

Already-resolved findings (C-1, 8/13 HIGHs, most M/L) are **not** repeated here —
see the triage doc. This plan is the open set only.

---

## 0. Triage summary of the open set

| # | Sev | Issue | Sources | Locus | Decision needed? |
|---|-----|-------|---------|-------|------------------|
| R1 | **HIGH** | Minimal `corpus`/`report` install import-crashes (numpy hard-imported at top) | H-5, codex×2 | `aiml_pentest.py:44-49` vs `requirements.txt:5` | no |
| R2 | **HIGH** | Agent-attack modules unreachable from CLI → **wire them in** (decided) | H-4, codex | `aiml_pentest.py:210,449` | resolved |
| R2b | MED | Membership-inference reports noise (fabricated ground truth) → quarantine now, **build a real one** (decided) | H-10, codex | `scripts/inference/` | resolved (scope: new build) |
| R3 | MED | Scaffolded attacks set `attack_succeeded=True` → counted in "successful_attacks" summary despite INFO+disclaimer | codex (leaky rollup) | `extractor.py:174`, `membership_inference.py`, `aiml_pentest.py:229` | no |
| R4 | MED | Evasion siblings overstate: PGD=`CRITICAL`, boundary/HopSkipJump=`HIGH`; FGSM still `HIGH` while peers are INFO | N-1, codex×2, H-13 | `evasion_attacks.py:161,263,397,535` | no |
| R5 | MED | Dashboard `_last_generated_corpus` global → cross-client state bleed, not multi-worker safe | A3, codex×2 | `dashboard/app.py:60,136,343` | partial (single-user vs per-session) |
| R6 | MED | CVE matcher: `<` tested before `<=`; `except: return True` biases false-positive | A4, codex×2 | `scanner.py:682-694` | no |
| R7 | MED | Scanner unbounded `f.read()` + silent skips returning `success=True` (OOM / incomplete-looks-complete) | A5, codex×2 | `scanner.py:386,445,590,720` | no |
| R8 | MED | Pickle analysis is byte-regex, not `pickletools` (evadable / false-positives) | M-16 | `scanner.py:364,726` | no |
| R9 | MED | `APIModelInterface.predict` hardcodes `{"input": ...}` body | M-6 | `scripts/utils/base.py:139` | no |
| R10 | MED | Relicense CC-BY-NC-SA → **Apache-2.0** (decided) | M-23 | `LICENSE.md:1` | resolved |
| R11 | LOW | Missing/inaccessible `--config` → raw `FileNotFoundError` | A1, L-6 | `aiml_pentest.py:517` | no |
| R12 | LOW | `POST /api/corpus/regenerate` missing `_require_xhr` guard | A2, codex×2 | `dashboard/app.py:361` | no |
| R13 | LOW | Dashboard `GenerateRequest.count` accepted but ignored | N-2, codex | `dashboard/app.py:76,327` | no |
| R14 | LOW | Corpus test fixture slow (~303 s suite) | L-16 | `tests/unit/test_corpus_generator.py:23` | no |
| R15 | LOW | `docs/pcev/` internal planning artifacts shipped | L-17 | `docs/pcev/` | no |
| R16 | LOW | Review docs cite absent `CODE-REVIEW-APPENDIX.md` + untracked `tmp/*` scratch | codex (full-HEAD) | `docs/*-08JUN2026.md`, `.gitignore` | no |
| R17 | NIT | `AGENTS.md` is stale claude-mem memory context, not repo instruction | codex (full-HEAD) | `AGENTS.md` | no |

**Owner decisions (resolved 08 JUN 2026):**
- **R2** — Wire `tool_hijacking` + `mcp_poisoning` into the CLI as runnable
  agent-attack modules (they do real black-box agent probing). Keep heuristic
  results at `INFO` + disclaimer where applicable.
- **R2b** — `membership_inference` reports noise (fabricated member/non-member
  labels, simulated shadow models). Quarantine the current scaffold (not runnable,
  no findings) and schedule a **real** implementation — either rebuilt fresh or
  built on the existing skeleton — using genuine member/non-member sets or trained
  shadow models (Shokri et al. 2017).
- **R10** — Relicense to **Apache-2.0** (commercial use allowed; attribution via
  retained notices + `NOTICE`; explicit patent grant).

---

## 1. Phased remediation

### Phase 0 — Unblock (clears the BLOCK verdict)  ·  ~1–2 h
**R1 — Stop the stable surface import-crashing.**
- Move the four attack-module imports (`evasion_attacks`, `extractor`,
  `injector`, `poisoning_tests`) out of `aiml_pentest.py` top level into a
  lazy import inside `_get_module()` (and inside the `scan` dispatch only).
  `corpus`/`report` must import and run with **only `requests`** installed.
- Add a guarded import that raises an actionable error (`"numpy required for
  experimental modules; pip install -r requirements.txt"`) instead of a raw
  `ModuleNotFoundError`.
- **Validate:** in a venv with only `requests`, `python aiml_pentest.py corpus
  --category ... --preview 5` succeeds; `scan` exits with the actionable message.

### Phase 1 — Operator-trust correctness (findings the tool emits)  ·  ~2–3 h
**R3 — Scaffolded results must not count as successes.**
- For every heuristic/scaffold finding emitted at `Severity.INFO`, set
  `attack_succeeded=False` (or exclude INFO/scaffold results from the
  `successful_attacks` tally in `_generate_summary`, `aiml_pentest.py:229`).
- Rename the misleading `JacobianAugmentation` test/label (M-13) to reflect that
  it is random-perturbation augmentation.

**R4 — Align evasion severities with the reframe.**
- Downgrade PGD (`evasion_attacks.py:263`), boundary (`:397`), HopSkipJump
  (`:535`) findings to `INFO` with the same "research scaffold, not
  measurement-grade" wording already used in extractor/inference.
- Reconcile FGSM (`:161`): either `INFO` like its peers, or document why a
  real-query black-box measurement justifies a higher ceiling — but be
  consistent.
- **Validate:** a scan run summary reports `successful_attacks: 0` against a
  trivial/stub target; no CRITICAL/HIGH emitted from scaffolded modules.

### Phase 2 — Dashboard hardening  ·  ~1–2 h
- **R5** — Scope `_last_generated_corpus` per request/session (or, if single-user
  is intended, enforce `127.0.0.1`-only + document the assumption at the global's
  definition and refuse multi-worker startup).
- **R12** — Add `_xhr=Depends(_require_xhr)` to `regenerate_corpus`
  (`app.py:361`) for parity with `/generate` and `/filter`.
- **R13** — Honour `GenerateRequest.count` (bounded sample after category filter)
  or remove the field from the model + UI.
- **Validate:** two concurrent clients with different `target`s don't see each
  other's corpus; cross-origin POST to `/regenerate` is rejected; `count=N`
  returns ≤N (or the field is gone).

### Phase 3 — Experimental scanner correctness  ·  ~3–4 h
- **R6** — Replace the hand-rolled `<`/`<=` logic with
  `packaging.specifiers.SpecifierSet`; on parse failure return an explicit
  `unknown` (logged), never default to "affected".
- **R7** — Cap reads (bounded prefix for pattern scanning), stream where
  possible, and surface a `skipped_files` tally in the result so an incomplete
  scan no longer reports `success=True` silently.
- **R8** — Replace `__reduce__`/byte-regex pickle detection with a
  `pickletools.genops` walk that flags `GLOBAL`/`STACK_GLOBAL` opcodes resolving
  to dangerous callables (remove the two `TODO(security)` markers).
- **Validate:** unit tests for `_version_affected` covering `<=`, `<`, `>=`,
  `==`, and unparseable; a crafted oversized artifact is skipped+reported, not
  OOM; a benign pickle no longer false-positives, a `os.system` pickle is caught.

### Phase 4 — API/CLI surface  ·  ~2–3 h
- **R2 — Wire in the agent-attack modules (decided).** Register
  `ToolHijackingModule` + `MCPPoisoningModule` in `_get_module()` and the
  `--modules` choices, with `--type llm`/agent target-type routing. Keep heuristic
  detections at `INFO` + "research-scaffold" wording where a test is partly
  simulated (e.g. `mcp_poisoning.py:463`). Honor R1's lazy-import pattern so these
  (numpy-free) modules don't reintroduce the import crash.
- **R2b — Quarantine membership-inference (decided).** Move
  `scripts/inference/` to `experimental/` (or gate behind an explicit
  `--allow-synthetic` that defaults off); remove its `__init__` export from any
  always-imported path; emit nothing in normal runs. Then **track a real build**
  (see new Phase 7).
- **R9** — Make `APIModelInterface.predict` request body configurable
  (template/callable in config) instead of hardcoded `{"input": ...}`.
- **R11** — Guard `--config`: `if not cfg_path.is_file(): parser.error(...)`
  before `stat()`.
- **Validate:** `scan --type llm --modules tool_hijacking` runs against a stub
  agent; `report --config nonexistent.yml` prints a clean error; no import-time
  reference to the quarantined inference module.

### Phase 5 — Licensing (decided: Apache-2.0)  ·  ~15 min
- **R10** — Replace `LICENSE.md` with the **Apache-2.0** text; add a `NOTICE`
  file with the project/author attribution; update the `README` license section
  and any module-header license lines. Remove the now-stale CC reference and the
  `LICENSE.md`→`DISCLAIMER.md` note if no longer accurate.
- **Validate:** `LICENSE.md` is verbatim Apache-2.0; `NOTICE` present; README and
  headers consistent.

### Phase 6 — Hygiene, tests, docs  ·  ~1–2 h
- **R14** — Make corpus generation a `module`/`session`-scoped fixture (generate
  once, reuse) to cut the ~303 s suite.
- **R15** — Remove `docs/pcev/` from the shipped tree (or relocate to an
  untracked `internal_docs/`).
- **R16** — Reconcile review docs: either bring `CODE-REVIEW-APPENDIX.md` onto the
  working branch or have the new docs link the remote commit explicitly; keep the
  durable `docs/*-08JUN2026.md` evidence, and add `tmp/` to `.gitignore` (scratch
  prompts/logs should not be committed).
- **R17** — Delete `AGENTS.md` (claude-mem scratch) and gitignore it.
- **Validate:** `pytest tests/` runtime materially lower; `git status` clean of
  scratch; no doc references a missing path.

### Phase 7 — Real membership-inference capability (R2b, new build)  ·  ~1–2 d (separate effort)
Not a bug-fix; a feature build to replace the quarantined scaffold. Design first,
then implement. Two viable paths:
- **(a) Build on the existing skeleton:** keep the 4-attack structure
  (threshold / shadow / label-only / entropy) but feed it **real** inputs — the
  caller supplies confirmed member + non-member sample sets, and accuracy/advantage
  is measured against those, not list-index labels.
- **(b) Rebuild fresh:** implement proper shadow-model training (Shokri et al.
  2017) — train N shadow models on known splits, train an attack model on their
  confidence vectors, evaluate against the target.
- Gate behind real data: refuse to emit a finding unless genuine member/non-member
  sets (or trained shadows) are provided; only then may it exceed `INFO`.
- **Validate:** on a model deliberately overfit to a known set, the attack reports
  high advantage; on a well-generalized model, near-random — i.e. the number
  tracks reality, unlike the current scaffold.

---

## 2. Suggested execution order & batching

1. **Phase 0 (R1)** — required to lift BLOCK. Land first, alone.
2. **Phase 1 (R3, R4)** — the credibility-critical correctness of emitted findings.
3. **Phases 2 + 3** — independent; can be done in parallel (different files).
4. **Phase 4** — wire agent attacks + quarantine inference (decisions resolved).
5. **Phase 5** — Apache-2.0 relicense (quick).
6. **Phase 6** — hygiene sweep; cheap, low-risk.
7. **Phase 7** — real membership-inference build; a **separate feature effort**,
   not part of clearing the BLOCK; schedule independently.

All owner decisions are resolved (R2, R2b, R10) — no further input needed to
start executing Phases 0–6.

## 3. Definition of done
- Re-run `codex exec --sandbox read-only` full-HEAD → verdict moves off **BLOCK**.
- `pytest tests/` green; new unit tests for `_version_affected`, pickle opcode
  detection, and the `successful_attacks` rollup.
- Minimal-install smoke test (`requests`-only) runs `corpus` + `report`.
- Triage doc updated: R1–R17 marked resolved with commit refs.
