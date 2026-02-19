<h1 align="center">
  <br>
  <code>0xPR0MPT</code>
  <br>
</h1>

<h4 align="center">AI/ML Security Testing Framework</h4>

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
</p>

---

Comprehensive penetration testing framework for AI and machine learning systems. Test LLMs for prompt injection, classifiers for adversarial robustness, and ML pipelines for supply chain vulnerabilities.

## Features

| Category | Capabilities |
|----------|-------------|
| **LLM Testing** | Prompt injection, jailbreaks, system prompt extraction, encoding bypasses |
| **Adversarial** | FGSM, PGD, C&W, boundary attacks, HopSkipJump |
| **Model Extraction** | Query-based stealing, Jacobian augmentation, knockoff networks |
| **Privacy** | Membership inference, model inversion, attribute inference |
| **Supply Chain** | CVE scanning, pickle analysis, model artifact inspection |
| **Data Poisoning** | Label flip, backdoor detection, trigger analysis |

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

### Test an LLM

```bash
python aiml_pentest.py scan \
  --target https://api.openai.com/v1/chat/completions \
  --type llm \
  --api-key $OPENAI_API_KEY
```

### Test a Classifier

```bash
python aiml_pentest.py scan \
  --target https://api.example.com/predict \
  --type classifier \
  --modules evasion extraction
```

### Scan Supply Chain

```bash
python aiml_pentest.py supply-chain --path ./my-ml-project
```

### Generate Test Corpus

```bash
python aiml_pentest.py corpus \
  --target "authentication bypass" \
  --categories prompt_injection jailbreak \
  --payloads 10
```

## Modules

### Prompt Injection

Tests LLM resistance to instruction hijacking and data exfiltration.

```python
from scripts.prompt_injection.injector import PromptInjectionModule

module = PromptInjectionModule(target=llm, output_dir=Path("./results"))
results = module.run_tests()
```

**Attack Categories:**
- Direct instruction override
- Jailbreaks (DAN, roleplay, personas)
- System prompt extraction
- Encoding bypasses (base64, ROT13, Unicode)
- Indirect injection (RAG poisoning)
- Multi-turn escalation

### Adversarial Evasion

Generates adversarial examples to test classifier robustness.

```python
from scripts.adversarial.evasion_attacks import EvasionAttackModule

module = EvasionAttackModule(
    target=classifier,
    config={"epsilon": 0.3, "max_iterations": 100}
)
results = module.run_tests()
```

### Model Extraction

Attempts to steal model functionality through query access.

```python
from scripts.model_extraction.extractor import ModelExtractionModule

module = ModelExtractionModule(
    target=api,
    config={"query_budget": 10000, "num_classes": 10}
)
results = module.run_tests()
```

### Supply Chain Scanner

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
│   ├── adversarial/         # Evasion attacks
│   ├── model_extraction/    # Model stealing
│   ├── prompt_injection/    # LLM injection
│   ├── data_poisoning/      # Training attacks
│   ├── supply_chain/        # Dependency scanning
│   ├── inference/           # Privacy attacks
│   ├── agent_attacks/       # MCP/tool hijacking
│   └── corpus_generator/    # Payload generation
├── methodology/             # Testing methodology
├── checklists/              # Assessment checklists
├── payloads/                # Injection payloads
├── templates/               # Report templates
├── dashboard/               # Web UI
└── tests/                   # Unit tests
```

## CLI Reference

```
Usage: python aiml_pentest.py <command> [options]

Commands:
  scan          Run security assessment against target API
  supply-chain  Scan project for supply chain vulnerabilities
  corpus        Generate attack payloads for a target
  report        Generate report from assessment results

Options:
  --target URL        Target API endpoint
  --type TYPE         Model type: classifier, llm, regression
  --api-key KEY       API authentication key
  --modules MODULES   Specific modules to run
  --output DIR        Output directory
  --config FILE       JSON configuration file
  --rate-limit FLOAT  Requests per second (default: 1.0)
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

## Documentation

- **[USAGE.md](USAGE.md)** - Detailed usage guide
- **[methodology/](methodology/)** - Full testing methodology
- **[checklists/](checklists/)** - Assessment checklists

## Legal

**Authorized testing only.** Obtain written permission before testing any system you don't own. Misuse may violate CFAA, GDPR, and other laws.

## License

MIT - See [LICENSE.md](LICENSE.md)
