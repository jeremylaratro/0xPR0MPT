<h1 align="center">
  <br>
  <code>0xPR0MPT</code>
  <br>
</h1>

<h4 align="center">AI/ML Red-Team Corpus Generator</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Install</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#modules">Modules</a> •
  <a href="#documentation">Docs</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/OWASP-ML%20Top%2010-red?style=flat-square" alt="OWASP">
  <img src="https://img.shields.io/badge/MITRE-ATLAS-orange?style=flat-square" alt="MITRE ATLAS">
  <img src="https://img.shields.io/badge/corpus%20generation-stable-brightgreen?style=flat-square" alt="Corpus Generation: Stable">
  <img src="https://img.shields.io/badge/live%20target%20execution-experimental-yellow?style=flat-square" alt="Live Target Execution: Experimental">
</p>

---

0xPR0MPT is an AI/ML red-team corpus generator and corpus browse/filter/export dashboard. It produces structured attack-payload corpora for prompt injection, jailbreaks, adversarial robustness, and related threat categories — ready for offline review, export, and integration into your testing workflows.

**Corpus generation: stable. Live target execution: experimental, not yet measurement-grade — see [Experimental Modules](#experimental-modules-research-scaffolding) below.**

## Features

### Corpus Generator (Primary Product)

| Category | Corpus Contents |
|----------|----------------|
| **Prompt Injection** | Direct instruction override, indirect injection, RAG poisoning, context overflow |
| **Jailbreaks** | DAN variants, roleplay personas, developer-mode prompts, skeleton-key techniques |
| **Encoding Bypasses** | Base64, ROT13, Unicode, homoglyph, token-smuggling payloads |
| **System Prompt Extraction** | Probe templates for system prompt leakage and boundary testing |
| **Multi-Turn Escalation** | Conversation-flow attack sequences |

### Dashboard

The web dashboard (`dashboard/`) exposes a corpus browser with filter, search, and export (CSV, Markdown, JSON). The executor page is included as a UI scaffold and displays "Coming soon" — live target execution is planned future work.

## Experimental Modules (Research Scaffolding)

> [!WARNING]
> The following modules are **research scaffolding — not measurement-grade**. Several metrics they produce (e.g., model-extraction "agreement rate", membership-inference confidence) are heuristic estimates, not empirical measurements. Live execution against real targets is planned future work under the "Live Target Connection" milestone. Do not rely on these outputs as ground truth.

| Module | Status | Notes |
|--------|--------|-------|
| **Adversarial Evasion** | Experimental | FGSM, PGD, boundary, HopSkipJump — black-box approximate variants |
| **Model Extraction** | Experimental | Query-based stealing scaffold; agreement rate is heuristic |
| **Privacy / Membership Inference** | Experimental | No shadow models trained; output is informational only |
| **Supply Chain Scanner** | Experimental | CVE scanning, pickle analysis, model artifact inspection |
| **Data Poisoning** | Experimental | Label flip, backdoor, trigger analysis scaffolds |

## Installation

```bash
git clone https://github.com/jeremylaratro/0xPR0MPT.git
cd 0xPR0MPT
pip install -r requirements.txt
```

<details>
<summary><strong>Optional Dependencies</strong></summary>

```bash
# Deep learning backends
pip install torch tensorflow

# Adversarial libraries
pip install foolbox adversarial-robustness-toolbox

# LLM providers
pip install openai anthropic

# Security scanning
pip install safety pip-audit bandit
```
</details>

## Quick Start

### Generate a Test Corpus (Stable)

```bash
python aiml_pentest.py corpus \
  --target "authentication bypass" \
  --categories prompt_injection jailbreak \
  --preview 10
```

### Launch the Corpus Dashboard (Stable)

```bash
cd dashboard
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
# Open http://127.0.0.1:8000 in your browser
```

---

### Experimental: Test an LLM (Live Target — Not Measurement-Grade)

> [!WARNING]
> **Experimental.** Results are not measurement-grade. Live execution against real targets is planned future work.

```bash
python aiml_pentest.py scan \
  --target https://api.openai.com/v1/chat/completions \
  --type llm \
  --api-key $OPENAI_API_KEY
```

### Experimental: Scan Supply Chain (Live Target — Not Measurement-Grade)

> [!WARNING]
> **Experimental.** Results are not measurement-grade.

```bash
python aiml_pentest.py supply-chain --path ./my-ml-project
```

## Modules

### Corpus Generator

Generates structured attack-payload test corpora for offline review and export.

```python
from scripts.corpus_generator.generator import TestCorpusGenerator

gen = TestCorpusGenerator(target="customer support chatbot")
corpus = gen.generate_all()
```

**Corpus Categories:**
- Direct instruction override
- Jailbreaks (DAN, roleplay, personas)
- System prompt extraction
- Encoding bypasses (base64, ROT13, Unicode)
- Indirect injection (RAG poisoning)
- Multi-turn escalation

### Prompt Injection (Experimental)

Tests LLM resistance to instruction hijacking and data exfiltration against a live target.

```python
from scripts.prompt_injection.injector import PromptInjectionModule

module = PromptInjectionModule(target=llm, output_dir=Path("./results"))
results = module.run_tests()
```

### Adversarial Evasion (Experimental)

Generates adversarial examples to test classifier robustness. Uses black-box approximate gradient estimation.

```python
from scripts.adversarial.evasion_attacks import EvasionAttackModule

module = EvasionAttackModule(
    target=classifier,
    config={"epsilon": 0.3, "max_iterations": 100}
)
results = module.run_tests()
```

### Model Extraction (Experimental)

Attempts to steal model functionality through query access. Agreement rate is a heuristic estimate, not a trained surrogate measurement.

```python
from scripts.model_extraction.extractor import ModelExtractionModule

module = ModelExtractionModule(
    target=api,
    config={"query_budget": 10000, "num_classes": 10}
)
results = module.run_tests()
```

### Supply Chain Scanner (Experimental)

Audits ML projects for dependency vulnerabilities and malicious artifacts.

```python
from scripts.supply_chain.scanner import SupplyChainScanner

scanner = SupplyChainScanner(config={"scan_path": "./project"})
results = scanner.run_tests()
```

## Project Structure

```
0xPR0MPT/
├── aiml_pentest.py          # CLI orchestrator
├── scripts/
│   ├── corpus_generator/    # Payload corpus generation (primary)
│   ├── prompt_injection/    # LLM injection (experimental)
│   ├── adversarial/         # Evasion attacks (experimental)
│   ├── model_extraction/    # Model stealing (experimental)
│   ├── data_poisoning/      # Training attacks (experimental)
│   ├── supply_chain/        # Dependency scanning (experimental)
│   ├── inference/           # Privacy attacks (experimental)
│   └── agent_attacks/       # MCP/tool hijacking (experimental)
├── methodology/             # Testing methodology
├── checklists/              # Assessment checklists
├── payloads/                # Injection payloads
├── templates/               # Report templates
├── dashboard/               # Corpus browser web UI
└── tests/                   # Unit tests
```

## CLI Reference

```
Usage: python aiml_pentest.py <command> [options]

Commands:
  corpus        Generate attack payload corpus for a target (stable)
  scan          Run security assessment against target API (experimental)
  supply-chain  Scan project for supply chain vulnerabilities (experimental)
  report        Generate report from assessment results

Options:
  --target URL        Target API endpoint or description string
  --type TYPE         Model type: classifier, llm, regression
  --api-key KEY       API authentication key
  --modules MODULES   Specific modules to run
  --output DIR        Output directory
  --config FILE       JSON configuration file
  --rate-limit FLOAT  Requests per second (default: 1.0)

Corpus-specific options:
  --categories        Payload categories to include
  --preview N         Preview N entries per category
```

## Configuration

```json
{
  "rate_limit": 1.0,
  "model_name": "gpt-4",
  "evasion": {
    "epsilon": 0.3,
    "max_iterations": 100
  },
  "extraction": {
    "query_budget": 10000,
    "num_classes": 10
  },
  "prompt_injection": {
    "custom_payloads": []
  }
}
```

## Methodology

Based on OWASP ML Top 10, MITRE ATLAS, and NIST AI RMF:

| Phase | Focus |
|-------|-------|
| 0 | Pre-engagement & authorization |
| 1 | Reconnaissance & fingerprinting |
| 2 | Model security (extraction, inversion) |
| 3 | Adversarial robustness |
| 4 | Prompt injection & jailbreaks |
| 5 | Data security & poisoning |
| 6 | Infrastructure & API security |
| 7 | Supply chain analysis |
| 8 | Privacy attacks |
| 9 | Resource exhaustion |
| 10 | Reporting & remediation |

> **Note:** Phases 1-10 above correspond to sections 1-10 in `methodology/AI-ML-PENTEST-METHODOLOGY-16FEB2026.md`. Phase 0 (pre-engagement guidance) is covered in the methodology document's introduction and is not numbered as a standalone section there.

## Roadmap

The following work is planned for future milestones:

- **Live Target Connection milestone:** Implement real HTTP request execution in the dashboard executor, replacing the current simulation scaffold with `httpx`-backed test runs and verified result reporting.
- **Measurement-grade adversarial modules:** Train actual surrogate models for extraction quality measurement; implement real shadow-model membership inference (Shokri et al. 2017); label FGSM variants accurately as black-box or white-box.
- **CLI module registry:** Wire `inference/` and `agent_attacks/` modules into the CLI orchestrator's module registry and `--modules` choices.
- **Corpus IDs:** Derive corpus entry IDs from payload hashes for deterministic cross-run references.
- **SRI and auth:** Add subresource integrity hashes for CDN assets; add token-based authentication to dashboard endpoints.

## Documentation

- **[USAGE.md](USAGE.md)** - Detailed usage guide
- **[DISCLAIMER.md](DISCLAIMER.md)** - Authorized-use and warranty disclaimer
- **[SECURITY.md](SECURITY.md)** - Reporting security vulnerabilities
- **[methodology/](methodology/)** - Full testing methodology
- **[checklists/](checklists/)** - Assessment checklists

## Legal

**Authorized testing only.** Obtain written permission before testing any system you do not own. Misuse may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK), GDPR, and equivalent laws worldwide. See [DISCLAIMER.md](DISCLAIMER.md) for complete terms and conditions.

## Reporting Security Issues

Please see [SECURITY.md](SECURITY.md) for vulnerability reporting instructions.

## License

Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC-BY-NC-SA 4.0) — See [LICENSE.md](LICENSE.md) and [DISCLAIMER.md](DISCLAIMER.md).
