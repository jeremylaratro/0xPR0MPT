# 0xPR0MPT — Review Reconciliation & Triage

**Date:** 08 JUN 2026
**Author:** Independent reconciliation pass (local)
**Inputs:**
- Review 1 — `docs/APP-REVIEW-FINDINGS-11MAY2026.md` (63 findings: 1C / 13H / 25M / 24L), reviewed against baseline `d2a2930`.
- Review 2 — `docs/CODE-REVIEW-APPENDIX.md` @ `claude/full-code-review-vapgjn` / `3d513b3` (7 findings: 5 LOW + 2 NIT; verdict APPROVE-WITH-CHANGES).
- Remediation = PR #1 commits `872c996..46d53cb`, merged to `main` at `13876bc` (current HEAD).

---

## 1. How to read this

Every Review-1 finding is tagged with a **resolution class**, because "closed"
is not one thing here:

- **fixed-in-code** — the defect is actually corrected in the executable path.
- **closed-by-removing-claim** — the false claim/doc was deleted (the bug it
  described no longer applies).
- **moot** — the surface that carried the defect was removed entirely (e.g. the
  live executor).
- **mitigated-by-reframe** — the underlying code is *unchanged*; the output was
  downgraded to `INFO` and wrapped in a "research-scaffold estimate, not
  measured" disclaimer. Legitimate (Review 1 offered this as option 3) but **not
  a code fix**. These are the items the appendix neutralizes with the
  "experimental ⇒ not measurement-grade ⇒ not a bug" frame, and the ones a fresh
  reviewer should be told were closed this way.
- **open** — not addressed (or only partially), still live.

Verification depth: C-1 and all 13 HIGH findings were spot-checked directly
against current source. Mediums/Lows were confirmed from the remediation diff +
direct greps where material; a few low-impact Lows are marked *diff-inferred*.

---

## 2. Critical / High triage (verified against current source)

| ID | Finding | Class | Evidence (current tree) |
|----|---------|-------|--------------------------|
| C-1 | Dashboard test execution fabricated (`i%3` mock) | **moot / fixed-in-code** | `simulate_test_execution` gone; `executor.html:20` is an explicit "not yet been implemented … placeholder"; `app.py:178` placeholder route. |
| H-1 | README uses non-existent `--payloads` flag | **fixed-in-code** | `README.md:94` now `--preview 10`; `:244` documents `--preview N`. |
| H-2 | C&W attack claimed but not implemented | **closed-by-removing-claim** | No `carlini`/`c&w` match in `README.md`/`USAGE.md`/`evasion_attacks.py`. Claim removed; attack still not implemented (acceptable — no longer advertised). |
| H-3 | Model-extraction agreement is a formula, not a surrogate | **mitigated-by-reframe** | `extractor.py:164,269` severity→`INFO`; description: *"Heuristic estimate … no surrogate was trained … not a measured fidelity."* Formula unchanged. |
| H-4 | `inference/` & `agent_attacks/` not reachable from CLI | **OPEN** | `_get_module` registry (`aiml_pentest.py:211`) and `--modules choices` (`:449`) still list only `evasion/extraction/prompt_injection/poisoning`. Both modules ship but remain dead from the CLI. |
| H-5 | Top-level numpy import crashes minimal install | **OPEN (partial)** | `requirements.txt` now documents tiers ("corpus needs only `requests`"), **but** `aiml_pentest.py:44-49` still hard-imports the numpy-dependent modules at top level. Running `corpus` with only `requests` installed still raises `ModuleNotFoundError: numpy` at import — doc claim contradicts code. |
| H-6 | Stored XSS in corpus templates | **fixed-in-code** | `corpus.html:138-139` `esc()` (textContent-based) helper; applied before every `innerHTML` insertion (`:164,:203`); modal title via `.textContent`. Comments cite H-6. |
| H-7 | Stored XSS in `executor.html` via WS `test_name` | **moot** | Live executor + WebSocket replay removed; page is a placeholder. |
| H-8 | CLI HTML report embeds unescaped markdown/LLM output | **fixed-in-code** | `aiml_pentest.py:23` `import html`; `:381` `html.escape(md_report)`. |
| H-9 | Dashboard binds `0.0.0.0:8000`, no auth | **fixed-in-code** | `app.py:472` default `127.0.0.1`; `--host` flag + warning; XHR guard on mutating routes (see M-7). |
| H-10 | Shadow-model membership inference has no shadow models | **mitigated-by-reframe** | `membership_inference.py:176` severity→`INFO`; description: *"synthetic membership labels assigned by list index … not a real attack result."* `:204` still "Simulate shadow model training". |
| H-11 | Generator interpolates user `target` via f-string (brace injection) | **fixed-in-code** | `generator.py:105` `target = re.sub(r'[{}]', '', target)`; `_interpolate_target` helper (`:108`). |
| H-12 | No simulation disclaimer on executor page | **moot** | Executor is now a labelled placeholder. |
| H-13 | FGSM mislabelled white-box | **fixed-in-code (relabel)** | `evasion_attacks.py:162` now *"black-box approximation via random finite differences"*. **Residual:** severity still `HIGH` (`:161`) — defensible since it measures real query outcomes, but flag for codex to judge. |

**High-finding scorecard:** 8 fixed-in-code · 2 moot · 1 closed-by-removing-claim · 2 mitigated-by-reframe (H-3, H-10) · **2 OPEN (H-4, H-5)**.

---

## 3. Medium / Low triage (condensed)

**Fixed-in-code (verified):** M-3 (`re.sub` filename sanitize), M-4 (`max_history_turns=20` trim), M-5 (`AIML_API_KEY` env + warning), M-7 (`_require_xhr` guard on filter/generate), M-9 (CSV formula-injection guard), M-14 (backdoor now gated on measured `behavior_change>0.8`, not hardcoded `True`), M-15 (`'revision=' not in m` per-element), M-17 (`_looks_like_refusal` excludes refusals), M-18 (same helper in injector), M-25 (duplicate-FileHandler guard), L-2 (engagements dupes deleted), L-19 (40/40 payload `source` fields), L-20 (`DISCLAIMER.md` added), L-21 (`.gitignore` added).

**Fixed / moot via reframe of the surface:** M-8 (WebSocket route removed), M-10 (lru_cache), M-11 (`_last_generated_corpus` cache), M-19 (= H-8 fix), L-10 (`Content-Disposition: attachment` downloads).

**Mitigated-by-reframe (code unchanged, downgraded to INFO + disclaimer):** M-13 (Jacobian = Gaussian noise, "placeholder for Jacobian-based augmentation").

**Added (verified):** M-20 (`tests/unit/test_base.py`, 235 lines), M-21 (`np.random.seed(42)` in conftest), M-24 (`SECURITY.md`).

**Partial:** M-12 (htmx now has SRI `integrity` hash; Tailwind Play CDN intentionally un-SRI'd with an explanatory comment — runtime compiler, acceptable).

**OPEN (Medium):**
- **M-6** — `APIModelInterface.predict` still hardcodes `json={"input": ...}` (`base.py:141`). Matches no mainstream classifier API.
- **M-16** — pickle analysis still byte-regex; `scanner.py:364,726` carry `TODO(security): replace with pickletools.genops` — acknowledged, deferred.
- **M-23** — `LICENSE.md` still CC-BY-NC-SA 4.0 (Review 1: "not a software license"). Appears intentional (commit `9250f32` moved MIT→CC) — needs an explicit decision, not a silent carry.

**OPEN (Low):**
- **L-16** — slow corpus test fixture; suite still ~303 s (per appendix timing).
- **L-17** — `docs/pcev/` internal planning artifacts still shipped (3 subdirs present).
- **L-6** — `--config` still loaded with minimal validation (overlaps appendix A1 below).
- Lower-confidence / *diff-inferred* (not individually re-verified, likely addressed by the reframe + USAGE rewrite): M-1, M-2 (verified: no `/home/jay` in docs), M-22, L-1, L-3, L-4, L-5, L-7, L-8, L-9, L-11, L-12, L-13, L-14, L-15, L-18, L-22, L-23, L-24.

---

## 4. Carry-forward set for the independent codex pass

These are the items fed to codex (Review-1 open/reframed + all Review-2 findings).
Codex is asked to **independently verify each against the code**, not accept them.

### 4a. Review-1 OPEN (re-verify + judge severity)
| Ref | Item | Locus |
|-----|------|-------|
| H-4 | inference/ + agent_attacks/ modules unreachable from CLI | `aiml_pentest.py:211,449` |
| H-5 | `corpus` crashes at import w/o numpy despite "requests-only" doc claim | `aiml_pentest.py:44-49` vs `requirements.txt` |
| M-6 | hardcoded `{"input": ...}` request body | `base.py:141` |
| M-16 | pickle scan is byte-regex, not `pickletools` | `scanner.py:364,726` |
| M-23 | CC-BY-NC-SA license on software | `LICENSE.md` |
| L-16 | slow test fixture (~303 s) | `tests/unit/test_corpus_generator.py` |
| L-17 | internal `docs/pcev/` artifacts shipped | `docs/pcev/` |

### 4b. Review-1 mitigated-by-reframe (challenge: is disclaimer-based closure adequate?)
H-3, H-10, H-13 (severity), M-13 — non-empirical attacks downgraded to `INFO` +
"not measurement-grade" text rather than implemented. Ask codex whether any of
these can still emit a misleading finding, and whether H-13 emitting `HIGH` is
consistent with the others' `INFO`.

### 4c. Review-2 (appendix) findings — re-verify
| Ref | Item | Locus |
|-----|------|-------|
| A1 [LOW] | missing `--config` → unhandled `FileNotFoundError` traceback | `aiml_pentest.py:517-520` |
| A2 [LOW] | `POST /api/corpus/regenerate` missing `_require_xhr` (inconsistent w/ siblings) | `app.py:361-370` |
| A3 [LOW] | shared mutable `_last_generated_corpus` global → cross-client state bleed, not multi-worker safe | `app.py:60,131-138,343` |
| A4 [LOW] | `_version_affected` tests `<` before `<=`; `except: return True` biases to false-positive | `scanner.py:675-697` |
| A5 [LOW] | unbounded `f.read()` + silent skips in scanner (OOM on large artifact; incomplete scan looks complete) | `scanner.py:386,445,511,590,720` |
| A6 [NIT] | inline `__import__('base64')` in payload builder | `generator.py:288` |
| A7 [NIT] | monolithic 6.4k-line generator | `generator.py` |

---

## 5. Bottom line going into the codex pass

- The **critical operator-deception finding (C-1) and 8/13 HIGHs are genuinely
  fixed in code.** Two HIGHs (H-3, H-10) and one Medium (M-13) were closed by
  **downgrade-and-disclaim, not implementation** — honest, but the attacks remain
  non-functional and the appendix's "experimental" frame leans on that.
- **Two HIGHs are still OPEN:** H-4 (dead CLI modules) and H-5 (import-time crash
  vs. the "requests-only" install claim — a concrete, reproducible contradiction).
- The appendix's APPROVE-WITH-CHANGES verdict is consistent with the *executable
  stable surface* (corpus + report) being clean; it under-weights H-4/H-5 because
  it scoped to the stable surface and treated the rest as experimental.
- Independent codex pass output: `docs/CODEX-REVIEW-08JUN2026.md`.
