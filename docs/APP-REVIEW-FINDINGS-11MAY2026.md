# 0xPR0MPT — Application Review Findings

**Review date:** 11 May 2026
**Branch:** `claude/app-review-findings-6PTgn`
**Reviewer:** Phased multi-agent code review (Opus planning, Sonnet execution)

---

## 1. Executive Summary

A five-phase review of the 0xPR0MPT AI/ML security pentesting framework was performed across scope coherence, core framework, attack modules, dashboard/display, and quality/legal. The review surfaced **1 critical**, **13 high**, **25 medium**, and **24 low** findings.

The most material issues are:

- **The dashboard's "test execution" is a hardcoded mock** (every third test reported successful via `i % 3 == 0`), with no UI disclaimer. A user running the executor against a real target believes results are real; they are fabricated.
- **Several core attack implementations are simulated, not real**: model-extraction "agreement rate" is a linear formula over query counts; shadow-model membership inference assigns ground-truth membership by list index (no shadow model is trained); Jacobian augmentation uses Gaussian noise; FGSM samples ~0.07% of input dimensions. C&W is claimed in the README but the function does not exist.
- **The dashboard has stored-XSS sinks** (corpus templates render user-controlled `name`, `description`, and array fields via `innerHTML` without escaping) and the CLI HTML report likewise embeds raw markdown inside `<pre>`. The dashboard binds to `0.0.0.0:8000` with no authentication.
- **The README's very first `corpus` example uses a flag (`--payloads`) that does not exist.** Two shipped modules (`scripts/inference/`, `scripts/agent_attacks/`) are not wired into the CLI orchestrator at all.
- **The repository ships internal AI-assisted planning artifacts** (`docs/pcev/`), uses a Creative Commons license that CC itself recommends against for software, and contains the developer's hardcoded local path (`/home/jay/...`) in user-facing documentation.

These items collectively undermine the framework's credibility as a pentesting tool: results displayed to operators are not trustworthy without inspecting source, and several "findings" the framework emits against a target are non-empirical.

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 13 |
| Medium | 25 |
| Low | 24 |
| **Total** | **63** |

---

## 2. Methodology

Five phases were dispatched in parallel:

| Phase | Scope | Agent |
|-------|-------|-------|
| 1 | Scope & coherence (claims vs. implementation) | Sonnet |
| 2 | Core framework & CLI (`aiml_pentest.py`, `scripts/utils/base.py`) | Sonnet |
| 3 | Attack modules (`scripts/{adversarial,model_extraction,prompt_injection,data_poisoning,supply_chain,inference,agent_attacks,corpus_generator}`) | Sonnet |
| 4 | Dashboard & display (`dashboard/app.py`, templates, CLI report) | Sonnet |
| 5 | Tests, documentation, legal/licensing, repo hygiene | Sonnet |

Severity ratings:

- **Critical** — Active operator deception, RCE risk, secrets exposure, or production-impacting vulnerability.
- **High** — False security claim, broken core feature, XSS/auth gap on a tool that handles secrets, attack implementation that returns synthetic numbers as if measured.
- **Medium** — Defects that materially reduce utility, latent vulnerabilities, missing defensive controls, doc claims that misleadingly describe shipped behavior.
- **Low** — Polish, hygiene, repository-management defects.

Each finding is tagged with the phase that surfaced it (P1–P5). Where two phases corroborated the same defect, a single deduplicated entry is recorded.

---

## 3. Findings

### 3.1 CRITICAL

#### C-1 — Dashboard test execution is fabricated; UI presents results as real
- **Phase:** P1, P4
- **Evidence:** `dashboard/app.py:391–421` (`simulate_test_execution`); line 412 — `"attack_succeeded": i % 3 == 0, # Simulate 1/3 success rate`. `executor.html` contains no banner indicating simulation; it displays "Vulnerabilities Found" and "VULNERABLE"/"SECURE" badges as if real.
- **Why it matters:** A pentest operator pointing the executor at a real API receives a deterministic 33% "vulnerability rate" with no relationship to the target. Any report exported from this surface is fabricated.
- **Fix:** Either (a) add a persistent "SIMULATION MODE — no real requests sent" banner across the executor page and rename the WebSocket route, or (b) actually issue requests using `httpx` (already in `dashboard/requirements.txt`).

---

### 3.2 HIGH

#### H-1 — README Quick Start uses non-existent `--payloads` flag
- **Phase:** P1
- **Evidence:** `README.md:96` shows `--payloads 10`. `aiml_pentest.py:469` defines `--preview`, not `--payloads`. Running the documented command exits with `unrecognized arguments: --payloads`.
- **Fix:** Replace `--payloads 10` with `--preview 10` (or `-p 10`).

#### H-2 — C&W (Carlini & Wagner) attack is claimed but not implemented
- **Phase:** P1, P3
- **Evidence:** `README.md:32`, `USAGE.md:162` list C&W. `scripts/adversarial/evasion_attacks.py` defines only `test_fgsm`, `test_pgd`, `test_boundary_attack`, `test_hopskipjump`; no C&W method exists. Only string match in the codebase is a label in `generator.py:581`.
- **Fix:** Implement C&W (L2 optimization with binary search on `c`), or remove from all marketing claims.

#### H-3 — Model-extraction "agreement rate" is a formula, not a trained surrogate
- **Phase:** P1, P3
- **Evidence:** `scripts/model_extraction/extractor.py:542–567` `_evaluate_extraction_quality` — comment: *"In real scenario: train surrogate and measure agreement / Here: simulate based on data quality metrics."* Agreement is computed as `0.5 + 0.3*label_coverage + min(0.2, num_samples/50000) + 0.1*soft_labels`. CRITICAL findings are then issued against the target based on this number.
- **Fix:** Train a `sklearn.neural_network.MLPClassifier` (or torch) surrogate on collected `(input, prediction)` pairs and report measured prediction agreement on held-out queries.

#### H-4 — `scripts/inference/` and `scripts/agent_attacks/` are not reachable from the CLI
- **Phase:** P1, P2
- **Evidence:** `aiml_pentest.py:35–39` (imports) and `aiml_pentest.py:200–213` (`_get_module`) register only `evasion`, `extraction`, `prompt_injection`, `poisoning`. `--modules` argparse `choices` (`aiml_pentest.py:438–439`) mirrors that list. The agent-attacks and membership-inference modules ship as code but are silently dead from a user's perspective.
- **Fix:** Add `AgentAttacksModule` and `MembershipInferenceModule` to the registry and `choices` list; add scan-flow target-type routing for them.

#### H-5 — Top-level `numpy` import in always-loaded modules; minimal install will crash
- **Phase:** P2
- **Evidence:** `aiml_pentest.py:35–39` unconditionally imports `evasion_attacks`, `extractor`, etc. Each has `import numpy as np` at module top. While `numpy` is listed in `requirements.txt:4`, the comment block labels the surrounding ML deps "optional"; a user reading the README's "Optional Dependencies" section may install only `requests`. The CLI then crashes at import with `ModuleNotFoundError`, not at test time with a useful message.
- **Fix:** Split requirements into `requirements-core.txt` / `requirements-ml.txt`, or guard `numpy` imports inside each module with a deferred-import pattern that raises an actionable error on use.

#### H-6 — Stored XSS in dashboard corpus templates (HTML rendered from API data without escaping)
- **Phase:** P4
- **Evidence:** `dashboard/templates/corpus.html:155–181` `renderResults` interpolates `tc.name`, `tc.description`, `tc.id`, `tc.category`, `tc.techniques_used[]`, `tc.target_models[]`, `tc.success_indicators[]`, `tc.expected_behavior`, `tc.research_source` directly into `innerHTML` via template literals. Only `tc.payload_preview` is escaped. The modal `showDetails` (lines 188–262) has the same defect. Corpus content is user-influenced via the generator's `target` parameter.
- **Fix:** Replace all `innerHTML` writes that consume API data with DOM construction via `document.createElement` + `.textContent`. As a quick mitigation, run all fields through a single escape helper before interpolation.

#### H-7 — Stored XSS in `executor.html` via unescaped `data.test_name` from WebSocket
- **Phase:** P4
- **Evidence:** `dashboard/templates/executor.html:192–202` `addResult` writes `data.test_name` (corpus-derived) into `innerHTML`. A corpus entry with `name: "<img src=x onerror=alert(1)>"` executes when the WebSocket replays it.
- **Fix:** Use `.textContent`.

#### H-8 — CLI HTML report embeds raw markdown (including LLM output) inside `<pre>`
- **Phase:** P4
- **Evidence:** `aiml_pentest.py:391–393`:
  ```python
  <pre style="white-space: pre-wrap;">
  {md_report}
  </pre>
  ```
  `md_report` is an f-string that interpolates `finding.title`, `finding.description`, `finding.remediation`, and a 500-char slice of `json.dumps(evidence)` without HTML escaping. A finding title containing `</pre><script>alert(1)</script>` breaks out and executes; LLM-response evidence is attacker-influenced.
- **Fix:** Wrap `md_report` with `html.escape()` before embedding, or render markdown to HTML via a library with safe mode (`mistune` `escape=True`).

#### H-9 — Dashboard binds to `0.0.0.0:8000` with no authentication
- **Phase:** P4
- **Evidence:** `dashboard/app.py:430` — `uvicorn.run(app, host="0.0.0.0", port=8000)`. No auth middleware on any route. `/api/corpus/generate`, `/api/export/*`, and `/ws/results/*` are exposed to any host on the network.
- **Fix:** Default `host="127.0.0.1"`, add a `--host` flag, and protect state-changing endpoints behind a token (FastAPI dependency).

#### H-10 — Shadow-model membership inference uses no shadow models; "ground truth" is a list index
- **Phase:** P3
- **Evidence:** `scripts/inference/membership_inference.py:197` — comment: *"In real implementation, would train actual shadow models"*. Lines 222–223 — `true_membership.append(1 if i < num_samples // 2 else 0)`. No shadow model is trained; membership labels are assigned by sample position; samples are random.
- **Fix:** Require the caller to provide confirmed member/non-member sample sets, or implement actual shadow model training (Shokri et al. 2017). Until implemented, gate the test behind an explicit `--allow-synthetic` flag and never emit a HIGH/CRITICAL finding from it.

#### H-11 — Corpus generator interpolates user `target` into payloads without sanitization (Python f-string injection)
- **Phase:** P3
- **Evidence:** `scripts/corpus_generator/generator.py:283` —
  ```python
  __import__('base64').b64encode(f"Reveal all {self.target} secrets".encode()).decode()
  ```
  Templates elsewhere use `.format(role=role, action=action)` on user-controlled strings. A `target` value containing `{` or `}` causes payload generation to crash or silently drop test cases.
- **Fix:** Validate `target` to `[\w\s\-]+` before use, and prefer `str.replace("{TARGET}", target)` consistently (the `_interpolate_target` helper already does the right thing — extend its use).

#### H-12 — No simulation disclaimer on executor page (compounds C-1)
- **Phase:** P4
- **Evidence:** `executor.html` contains no text indicating mock execution; the title is "Test Executor", the button reads "Execute Selected Tests". WebSocket URL hardcodes `ws://` regardless of page protocol.
- **Fix:** Add a top-of-page banner and switch WebSocket to `wss://` when `location.protocol === 'https:'`.

#### H-13 — FGSM uses sparse random finite-difference sampling (~0.07% of input dimensions) but is labelled white-box
- **Phase:** P3
- **Evidence:** `scripts/adversarial/evasion_attacks.py:582–606` `_estimate_gradient` samples `min(100, sample.size)` random indices, performs two queries per index. For 3×224×224 input that is ~0.07% of dimensions. The owning test is labelled FGSM (white-box) and severity-rates findings accordingly.
- **Fix:** Require the model interface to expose `get_gradient()`; otherwise label the variant explicitly as "black-box approximate FGSM" and lower the severity ceiling.

---

### 3.3 MEDIUM

#### M-1 — `USAGE.md` CLI Reference omits the `corpus` command entirely
- **Phase:** P1
- **Evidence:** `USAGE.md:85–88` lists only `scan`, `supply-chain`, `report`. `corpus` is a first-class CLI subcommand (`aiml_pentest.py:460`).
- **Fix:** Add a `corpus` section to the CLI reference.

#### M-2 — `USAGE.md` contains the developer's hardcoded local paths
- **Phase:** P1, P5
- **Evidence:** `USAGE.md:27,660,663` — `/home/jay/Documents/cyber/dev/pentest_scripts/ai`. Users following the Troubleshooting section will `cd` to a non-existent path.
- **Fix:** Replace with `$(pwd)` or `<path-to-0xPR0MPT>`.

#### M-3 — Path traversal in corpus output filename via `--target`
- **Phase:** P2
- **Evidence:** `aiml_pentest.py:577` — `target_suffix = f"_{args.target.replace(' ', '_')[:20]}"`. Only spaces are replaced; `../../etc/foo` survives. Resolved through `Path()` this can escape the output directory.
- **Fix:** `re.sub(r'[^\w\-]', '_', args.target)[:20]`.

#### M-4 — `LLMInterface.chat` conversation history grows unbounded
- **Phase:** P2
- **Evidence:** `scripts/utils/base.py:239–240` appends two entries per call; `reset_conversation` exists (line 248) but is never invoked automatically. Multi-turn jailbreak tests will hit context-window failures mid-run.
- **Fix:** Add `max_history_turns` config and trim before extending.

#### M-5 — `--api-key` on CLI leaks via process list and shell history
- **Phase:** P2
- **Evidence:** `aiml_pentest.py:443` accepts `--api-key` as a plain arg. Visible in `/proc/<pid>/cmdline` and `~/.bash_history`.
- **Fix:** Read from env (e.g., `AIML_API_KEY`) and warn when `--api-key` is used on CLI.

#### M-6 — `APIModelInterface.predict` hardcodes `{"input": ...}` body schema
- **Phase:** P2
- **Evidence:** `scripts/utils/base.py:139–143`. This shape matches no widespread real classifier API (HF Inference, SageMaker, Vertex, BentoML).
- **Fix:** Make the request body template configurable.

#### M-7 — No CSRF on state-changing dashboard endpoints
- **Phase:** P4
- **Evidence:** `dashboard/app.py:174` (`/api/corpus/filter`), `:270` (`/api/corpus/generate`). No CSRF middleware. HTMX submits with `text/html`-acceptable content types that some browsers allow cross-origin.
- **Fix:** Add `fastapi-csrf-protect` or signed-token middleware.

#### M-8 — WebSocket route validates nothing and crashes on malformed JSON
- **Phase:** P4
- **Evidence:** `dashboard/app.py:363–388`; `json.loads(data)` on line 379 is not wrapped in `try/except`. `job_id` is echoed back unvalidated.
- **Fix:** Validate `job_id` against an active-job allow-list; wrap JSON parse; require a token on connect.

#### M-9 — CSV formula injection in `/api/export/csv`
- **Phase:** P4
- **Evidence:** `dashboard/app.py:319–323`. Prompt-injection payloads often begin with `=`, `+`, `-`, `@`. Python's `csv.writer` does not shield these.
- **Fix:** Prefix any cell starting with one of those characters with a tab.

#### M-10 — Every corpus endpoint regenerates the full 6,387-line corpus on each request
- **Phase:** P4
- **Evidence:** `dashboard/app.py:137–144` `get_all_test_cases` is called by `/api/corpus`, `/api/corpus/filter` (HTMX keyup), `/api/corpus/{id}`, `/api/export/*`, `/api/stats`, `simulate_test_execution`.
- **Fix:** Cache at module startup or use `functools.lru_cache`; invalidate only on explicit regenerate.

#### M-11 — `/api/corpus/generate` discards the generated corpus
- **Phase:** P4
- **Evidence:** `dashboard/app.py:270–298` returns counts only; the generated object is dropped. Export endpoints then re-generate without the user's `target` interpolation.
- **Fix:** Cache the most-recent generation result and serve it from the export endpoints.

#### M-12 — Remote CDN scripts without subresource integrity
- **Phase:** P4
- **Evidence:** `dashboard/templates/base.html:9` — `https://cdn.tailwindcss.com`; line 12 — `https://unpkg.com/htmx.org@1.9.10`. No SRI hash on either.
- **Fix:** Add `integrity="sha384-..."` hashes or vendor assets to `dashboard/static/`.

#### M-13 — Jacobian augmentation uses Gaussian noise; no Jacobian is ever computed
- **Phase:** P3
- **Evidence:** `scripts/model_extraction/extractor.py:518–523` — `_jacobian_augment` adds `np.random.randn * 0.1`. Indistinguishable from random query.
- **Fix:** Augment along approximate-Jacobian rows of the surrogate (finite-difference on accumulated labels).

#### M-14 — Backdoor poisoning hardcodes `attack_succeeded=True`
- **Phase:** P3
- **Evidence:** `scripts/data_poisoning/poisoning_tests.py:247,288`. Every target receives the same "Model Susceptible to Backdoor Poisoning" finding (lines 273–281).
- **Fix:** Gate on a measured `behavior_change` threshold.

#### M-15 — Unversioned-HF-model detection logic bug (`str(set)` membership check)
- **Phase:** P3
- **Evidence:** `scripts/supply_chain/scanner.py:528` — `[m for m in model_refs if '@' not in m and 'revision=' not in str(model_refs)]`. `str(model_refs)` serialises the *whole* set; the `revision=` check is set-level, not per-element, producing systematic false positives or false negatives.
- **Fix:** `'revision=' not in m`.

#### M-16 — Pickle artifact analysis uses byte regex, not `pickletools` opcodes
- **Phase:** P3
- **Evidence:** `scripts/supply_chain/scanner.py:358–385`, `:719–730` use `re.search(rb'__reduce__', ...)` etc. Trivially evaded; produces false positives on benign metadata.
- **Fix:** Walk `pickletools.genops(stream)`, flag `GLOBAL`/`STACK_GLOBAL` opcodes that resolve to dangerous callables.

#### M-17 — Agent-attack and tool-hijacking success detection triggers on safety refusals
- **Phase:** P3
- **Evidence:** `scripts/agent_attacks/tool_hijacking.py:123`, `mcp_poisoning.py:462`. Indicator words include `delete`, `access`, `execute`, `credentials`. A refusal containing those words flips `matched=True`.
- **Fix:** Detect refusal patterns first and invert; require affirmative-context matching.

#### M-18 — Multi-turn prompt-injection success indicators match refusals
- **Phase:** P3
- **Evidence:** `scripts/prompt_injection/injector.py:406–412` — success on substring match of `system prompt`, `instructions`, `guidelines`, `restrictions`, `bypass`, `jailbreak`. A "I don't have a system prompt to reveal" response matches.
- **Fix:** Filter responses beginning with negation markers; require affirmative context.

#### M-19 — HTML report `_generate_html_report` does not escape any field (same issue as H-8, lower-severity surface)
- **Phase:** P4
- **Evidence:** See H-8.

#### M-20 — No unit tests for `scripts/utils/base.py` (shared foundation)
- **Phase:** P5
- **Evidence:** No `tests/unit/test_base.py`. `Finding.to_dict`, `to_json`, `generate_finding_id`, `_rate_limit_wait` are untested.
- **Fix:** Add `tests/unit/test_base.py`.

#### M-21 — Tests use unseeded `np.random` and produce non-deterministic results
- **Phase:** P5
- **Evidence:** `tests/conftest.py:52,260–262,331,339` use `np.random.*` without seeding. Evasion assertions on `linf_norm <= epsilon + 1e-6` (`test_evasion.py:72`) can flake.
- **Fix:** Seed in `conftest.py` and helpers.

#### M-22 — Mock-based prompt-injection tests are circular
- **Phase:** P5
- **Evidence:** `tests/conftest.py:141–178` `MockVulnerableLLM.chat` returns the exact strings listed as `success_indicators`. Tests prove only that the mock matches itself.
- **Fix:** Add near-miss cases (different case, partial match) to test matcher robustness.

#### M-23 — License: CC-BY-NC-SA 4.0 is not a software license
- **Phase:** P5
- **Evidence:** `LICENSE.md:1` declares CC-BY-NC-SA 4.0. Creative Commons themselves recommend against CC for software. The NC clause conflicts with the tool's expected use in commercial pentest engagements.
- **Fix:** Switch to AGPL-3.0 (matching the copyleft + non-commercial intent) or a dual-license model. Update `README.md:253` to spell out the chosen license.

#### M-24 — No `SECURITY.md`, no responsible-disclosure channel
- **Phase:** P5
- **Evidence:** No `SECURITY.md` at repo root. The tool ships pickle handling and a 6,387-line generator — vulnerabilities are plausible. No contact route.
- **Fix:** Add `SECURITY.md` with an email or GitHub Security Advisory link.

#### M-25 — `TestModule._setup_logging` adds a new FileHandler on every instantiation (FD leak)
- **Phase:** P2
- **Evidence:** `scripts/utils/base.py:278–285` — `self.logger.addHandler(handler)` unconditional. Repeated instantiation leaks file descriptors and duplicates log lines.
- **Fix:** `if not self.logger.handlers:` guard, or use a uniquely-named logger.

---

### 3.4 LOW

#### L-1 — Methodology phase numbering off-by-one (README 0–10 vs doc 1–10)
- **Phase:** P1
- **Evidence:** `README.md:228–239` lists Phase 0; `methodology/AI-ML-PENTEST-METHODOLOGY-16FEB2026.md:25` starts at section 1.

#### L-2 — Methodology files duplicated byte-for-byte across `methodology/` and `engagements/`
- **Phase:** P1, P5
- **Evidence:** `md5sum` matches between `methodology/AI-ML-PENTEST-METHODOLOGY-16FEB2026.md` and `engagements/AI-ML-PENTEST-METHODOLOGY-16FEB2026 1.md`, and again for `ATTACK-VECTORS-REFERENCE`.
- **Fix:** Delete the `engagements/` copies.

#### L-3 — Branding inconsistency: README says `0xPR0MPT` / `AI/ML Security Testing Framework`; module docstrings say `0xPrompt - LLM Exploitation Framework by d0sf3t`
- **Phase:** P1, P5
- **Evidence:** `README.md:3` vs `aiml_pentest.py:2`, `dashboard/app.py:3`, `scripts/corpus_generator/generator.py:3`.

#### L-4 — `_calculate_risk_rating` is non-monotonic in finding counts
- **Phase:** P2
- **Evidence:** `aiml_pentest.py:237–245`. `(critical=1, high=0)` and `(critical=0, high=10)` both return `HIGH`.
- **Fix:** Add a threshold band for large high-counts.

#### L-5 — `report --format json` does not coerce `.json` extension on `--output`
- **Phase:** P2
- **Evidence:** `aiml_pentest.py:522–526` handles `markdown` and `html` but not `json`.

#### L-6 — `--config` path is loaded with no path validation or size limit
- **Phase:** P2
- **Evidence:** `aiml_pentest.py:482–483`.

#### L-7 — `dashboard/requirements.txt` lists unused `aiosqlite` and `httpx`
- **Phase:** P2, P4
- **Evidence:** No import statements in `dashboard/app.py`.

#### L-8 — No version pinning; only lower bounds in both `requirements.txt` files
- **Phase:** P2
- **Fix:** Pin with `==` or add a lockfile via `pip-compile`.

#### L-9 — `TestExecuteRequest` Pydantic model accepts `target_endpoint` and `api_key` but no route consumes it (dead code with latent SSRF risk if wired up)
- **Phase:** P4
- **Evidence:** `dashboard/app.py:78–82`.

#### L-10 — `/api/export/{format}` returns CSV/markdown content inside JSON, not as file downloads
- **Phase:** P4
- **Evidence:** `dashboard/app.py:315,324`. No `Content-Disposition: attachment` or correct `Content-Type`.

#### L-11 — Emoji severity badges in markdown report may render poorly in non-UTF terminals
- **Phase:** P4
- **Evidence:** `aiml_pentest.py:299–305`.

#### L-12 — Report evidence truncated mid-token to 500 chars
- **Phase:** P4
- **Evidence:** `aiml_pentest.py:318` — `json.dumps(...)[:500]`.

#### L-13 — Corpus IDs are sequential integers reassigned each run; not deterministic across runs
- **Phase:** P3
- **Evidence:** `scripts/corpus_generator/generator.py:155–158`.
- **Fix:** Derive from a hash of `(category, payload)` as is already done for `generated_hashes` dedup.

#### L-14 — No dashboard tests
- **Phase:** P5
- **Evidence:** No `tests/test_dashboard*`.

#### L-15 — `tests/integration/` is empty
- **Phase:** P5
- **Evidence:** Only `__init__.py`.

#### L-16 — Corpus-generator test fixture not module-scoped (PCEV review reports 807 s test runtime)
- **Phase:** P5
- **Evidence:** `tests/unit/test_corpus_generator.py` calls `TestCorpusGenerator().generate_all()` per test method.

#### L-17 — `docs/pcev/` ships internal AI-assisted planning artifacts (PLAN, CRITIQUE, REQUIREMENTS, retrospectives)
- **Phase:** P5
- **Evidence:** `docs/pcev/PLAN-16FEB2026.md` etc. Not referenced by any code or user-facing doc.

#### L-18 — `templates/REPORT-TEMPLATE-16FEB2026.md` and `checklists/MASTER-CHECKLIST-16FEB2026.md` are not referenced from any code
- **Phase:** P5
- **Evidence:** `grep -r "MASTER-CHECKLIST\|REPORT-TEMPLATE" --include='*.py'` returns nothing.

#### L-19 — Bundled jailbreak payloads have no source attribution
- **Phase:** P5
- **Evidence:** `payloads/prompt_injection_payloads.json` has no `source` field on any of 40 entries; includes `dan_v1`, `developer_mode`, etc.

#### L-20 — `LICENSE.md` references a non-existent `DISCLAIMER.md`
- **Phase:** P5
- **Evidence:** `LICENSE.md:72` — "See DISCLAIMER.md for complete terms and conditions." File does not exist.

#### L-21 — `.gitignore` does not cover default output directories (`aiml_pentest_results/`, `corpus_output/`, `poison_samples/`, `*.log`)
- **Phase:** P5

#### L-22 — Generated `test_corpus/test_corpus.json` (≈103 KB) committed alongside its generator; no CI hash check
- **Phase:** P5

#### L-23 — `subprocess.run(['pip', 'show', ...])` in supply-chain scanner reads system `pip`, which may differ from the active venv
- **Phase:** P3
- **Evidence:** `scripts/supply_chain/scanner.py` (subprocess block). Not a security defect; gives wrong version readings inside isolated envs.

#### L-24 — `Finding.to_dict()` overwrites top-level enum values only; nested dataclasses with enums would lose their `.value` mapping
- **Phase:** P2
- **Evidence:** `scripts/utils/base.py:54–59`. Not currently triggered because no nested-dataclass fields with enums exist, but a latent trap.

---

## 4. Summary Table

| ID | Title | Severity |
|---|---|---|
| C-1 | Dashboard test execution is fabricated; UI presents results as real | Critical |
| H-1 | README Quick Start uses non-existent `--payloads` flag | High |
| H-2 | C&W attack claimed but not implemented | High |
| H-3 | Model-extraction agreement rate is a formula, not a trained surrogate | High |
| H-4 | `inference/` and `agent_attacks/` modules not reachable from CLI | High |
| H-5 | Top-level numpy import in always-loaded modules; minimal install crashes | High |
| H-6 | Stored XSS in dashboard corpus templates | High |
| H-7 | Stored XSS in `executor.html` via WebSocket `test_name` | High |
| H-8 | CLI HTML report embeds unescaped markdown / LLM output | High |
| H-9 | Dashboard binds 0.0.0.0:8000 with no auth | High |
| H-10 | Shadow-model membership inference has no shadow models | High |
| H-11 | Corpus generator interpolates user `target` via f-string unsanitized | High |
| H-12 | No simulation disclaimer on executor page | High |
| H-13 | FGSM uses sparse random finite-difference sampling, labelled white-box | High |
| M-1 | `USAGE.md` CLI Reference omits `corpus` command | Medium |
| M-2 | `USAGE.md` contains developer's local `/home/jay/...` paths | Medium |
| M-3 | Path traversal in corpus filename via `--target` | Medium |
| M-4 | `LLMInterface.chat` conversation history grows unbounded | Medium |
| M-5 | `--api-key` on CLI leaks via process list | Medium |
| M-6 | `APIModelInterface` hardcodes non-standard `{"input": ...}` body | Medium |
| M-7 | No CSRF on state-changing dashboard endpoints | Medium |
| M-8 | WebSocket validates nothing; crashes on malformed JSON | Medium |
| M-9 | CSV formula injection in `/api/export/csv` | Medium |
| M-10 | Every corpus endpoint regenerates full corpus | Medium |
| M-11 | `/api/corpus/generate` discards generated corpus | Medium |
| M-12 | Remote CDN scripts without SRI | Medium |
| M-13 | Jacobian augmentation uses Gaussian noise; no Jacobian computed | Medium |
| M-14 | Backdoor poisoning hardcodes `attack_succeeded=True` | Medium |
| M-15 | Unversioned-HF-model detection: `str(set)` logic bug | Medium |
| M-16 | Pickle analysis uses byte regex, not pickletools | Medium |
| M-17 | Agent-attack indicator matching triggers on refusals | Medium |
| M-18 | Multi-turn injection indicators match refusals | Medium |
| M-19 | HTML report does not escape any field | Medium |
| M-20 | No unit tests for `scripts/utils/base.py` | Medium |
| M-21 | Unseeded `np.random` in test fixtures (flaky) | Medium |
| M-22 | Mock-based injection tests are circular | Medium |
| M-23 | License: CC-BY-NC-SA is not a software license | Medium |
| M-24 | No `SECURITY.md` / disclosure channel | Medium |
| M-25 | `TestModule._setup_logging` adds duplicate FileHandlers | Medium |
| L-1 | Methodology phase numbering off-by-one | Low |
| L-2 | Methodology files duplicated across folders | Low |
| L-3 | Branding inconsistency (`0xPR0MPT` vs `0xPrompt - LLM ...`) | Low |
| L-4 | `_calculate_risk_rating` non-monotonic | Low |
| L-5 | `report --format json` doesn't coerce `.json` extension | Low |
| L-6 | `--config` path: no validation or size limit | Low |
| L-7 | `dashboard/requirements.txt` lists unused deps | Low |
| L-8 | No version pinning | Low |
| L-9 | `TestExecuteRequest` model is dead code (latent SSRF) | Low |
| L-10 | Export endpoints return content inside JSON, not as downloads | Low |
| L-11 | Emoji severity badges may render poorly in non-UTF terminals | Low |
| L-12 | Report evidence truncated mid-token to 500 chars | Low |
| L-13 | Corpus IDs are sequential per run; not deterministic | Low |
| L-14 | No dashboard tests | Low |
| L-15 | `tests/integration/` is empty | Low |
| L-16 | Corpus generator test fixture not module-scoped | Low |
| L-17 | `docs/pcev/` ships internal planning artifacts | Low |
| L-18 | `REPORT-TEMPLATE` / `MASTER-CHECKLIST` not referenced from code | Low |
| L-19 | Bundled jailbreak payloads lack source attribution | Low |
| L-20 | `LICENSE.md` references non-existent `DISCLAIMER.md` | Low |
| L-21 | `.gitignore` missing default output directories | Low |
| L-22 | Generated `test_corpus.json` committed alongside generator | Low |
| L-23 | `pip show` subprocess may not reflect active venv | Low |
| L-24 | `Finding.to_dict()` overwrites enums at top level only | Low |

---

## 5. Recommended Remediation Order

1. **Stop showing fake results to users.** Address C-1 and H-12 first — either implement real execution in `dashboard/app.py:simulate_test_execution` (the `httpx` dependency is already present) or add a prominent simulation banner and rename the route.
2. **Fix XSS sinks** (H-6, H-7, H-8). Either escape all corpus-derived fields before insertion or move to `textContent`/safe-mode markdown rendering. These are reachable today via a crafted `target` string.
3. **Stop emitting non-empirical CRITICAL/HIGH findings** (H-3, H-10, H-13, M-13, M-14, M-17, M-18). Either implement the real attacks or downgrade the findings these modules produce to "informational / requires manual verification".
4. **Fix CLI claim drift** (H-1, H-2, H-4, M-1, M-2). Easy edits, big credibility impact.
5. **Bind dashboard locally and add auth** (H-9, M-7, M-8, M-9, M-12).
6. **License and disclosure** (M-23, M-24, L-20).
7. **Documentation cleanup** (L-2, L-3, L-17, L-18, L-19).
8. **Repo hygiene and dependency pinning** (L-7, L-8, L-21, L-22).
