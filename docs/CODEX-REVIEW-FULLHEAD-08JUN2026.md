# 0xPR0MPT — Independent Codex Review (full-HEAD, BLOCK)

**Date:** 08 JUN 2026  ·  **Tool:** `codex exec --sandbox workspace-write` (codex-cli 0.133.0), local
**Target:** working tree at `13876bc` (HEAD; `git diff main` empty)  ·  **rc=0**
**Raw log:** `tmp/codex-fullhead-stream-08JUN2026.log` (5400 lines incl. tool/hook noise)

---

hook: Stop
hook: Stop Failed
hook: Stop Failed
tokens used
117,452
Reviewed `HEAD` plus untracked artifacts. There is no tracked diff against `main`; current untracked files are `AGENTS.md`, two review docs, and `tmp/`.

**Findings**
[HIGH] Documented minimal `corpus` install still import-crashes — [requirements.txt](/home/jay/Documents/cyber/dev/0xPR0MPT/requirements.txt:5), [aiml_pentest.py](/home/jay/Documents/cyber/dev/0xPR0MPT/aiml_pentest.py:45) — `requirements.txt` says corpus/report need only `requests`, but `aiml_pentest.py` imports numpy-dependent experimental modules at import time. I simulated numpy missing and `corpus` failed before argparse with `ModuleNotFoundError`. Direction: lazy-load experimental modules behind `scan`/`supply-chain`, or make numpy part of the stable install claim.

[MEDIUM] Targeted dashboard corpus bleeds across clients — [dashboard/app.py](/home/jay/Documents/cyber/dev/0xPR0MPT/dashboard/app.py:60) — `_last_generated_corpus` is module-global and `_get_active_corpus()` serves it to all later `/api/corpus`, filter, export, and stats requests. Direction: scope generated corpora per session/request, or document/enforce single-user operation.

[MEDIUM] CVE version matching mishandles `<=` — [scanner.py](/home/jay/Documents/cyber/dev/0xPR0MPT/scripts/supply_chain/scanner.py:682) — `affected.startswith('<')` runs before `<=`, so `1.0 <=1.0` returns false; comparison errors also return affected/true. Direction: use `packaging.specifiers.SpecifierSet` and explicit unknown/error reporting.

[MEDIUM] Scanner can silently skip or OOM on large artifacts — [scanner.py](/home/jay/Documents/cyber/dev/0xPR0MPT/scripts/supply_chain/scanner.py:386) — pickle/model/config scans use unbounded `f.read()`, then log failures only at debug while returning `success=True`. Direction: cap file sizes, stream where possible, and surface skipped files in result metrics/findings.

[MEDIUM] Experimental evasion findings still overstate scaffolded results — [evasion_attacks.py](/home/jay/Documents/cyber/dev/0xPR0MPT/scripts/adversarial/evasion_attacks.py:263) — PGD emits `CRITICAL`; boundary/HopSkipJump emit `HIGH` from scaffolded generated samples while other heuristic modules were downgraded to `INFO`. Direction: align severity and result wording with “research scaffold, not measurement-grade.”

[LOW] Missing `--config` raises raw traceback — [aiml_pentest.py](/home/jay/Documents/cyber/dev/0xPR0MPT/aiml_pentest.py:517) — `cfg_path.stat()` runs before existence handling. I verified a missing path produces `FileNotFoundError`. Direction: check `is_file()` or catch `OSError` and call `parser.error`.

[LOW] Regenerate endpoint misses the XHR guard — [dashboard/app.py](/home/jay/Documents/cyber/dev/0xPR0MPT/dashboard/app.py:361) — `/api/corpus/regenerate` mutates cache/global state but has no `Depends(_require_xhr)`, unlike sibling mutating routes. Direction: add the same dependency.

[LOW] Dashboard accepts `count` but ignores it — [dashboard/app.py](/home/jay/Documents/cyber/dev/0xPR0MPT/dashboard/app.py:76) — `GenerateRequest.count` is defined, but generation returns all filtered cases. Direction: apply a bounded sample/limit or remove the field.

[LOW] New review docs depend on absent/scratch artifacts — [docs/REVIEW-TRIAGE-08JUN2026.md](/home/jay/Documents/cyber/dev/0xPR0MPT/docs/REVIEW-TRIAGE-08JUN2026.md:7), [docs/CODEX-REVIEW-08JUN2026.md](/home/jay/Documents/cyber/dev/0xPR0MPT/docs/CODEX-REVIEW-08JUN2026.md:9) — both cite `docs/CODE-REVIEW-APPENDIX.md`, which is not in this branch, and the Codex review cites untracked `tmp/*.md`/`*.txt` while `.gitignore` only ignores `.review-tmp/` and `*.log`. Direction: include the appendix or link the remote commit explicitly; move durable review evidence under `docs/` or ignore/remove scratch files.

[NIT] `AGENTS.md` is only stale local memory context — [AGENTS.md](/home/jay/Documents/cyber/dev/0xPR0MPT/AGENTS.md:1) — no actionable repo instruction, only “No previous sessions found.” Direction: omit it unless the repo intentionally tracks agent-local state.

**VERDICT: BLOCK**

Top 3 to fix first: minimal-install import crash, dashboard global corpus state, scanner version/file-read correctness.

Could not verify: full `pytest tests/` because prior docs report ~303s and I scoped runtime checks to stable unit tests. I ran `pytest -q tests/unit/test_corpus_generator.py tests/unit/test_base.py`: 42 passed, 2 warnings. Two FastAPI TestClient endpoint probes hung in the sandbox, so endpoint runtime behavior beyond source/dependency introspection was not verified. No obvious committed secrets were found with common token/key patterns.
