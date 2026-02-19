# PCEV Stage 1: Research & Assessment
## AI/ML Test Corpus Expansion Project
**Date:** 16 February 2026

---

## 1. Current Framework Analysis

### 1.1 Existing Modules

| Module | File | Coverage | Gap Analysis |
|--------|------|----------|--------------|
| Evasion Attacks | `scripts/adversarial/evasion_attacks.py` | FGSM, PGD, Boundary, HopSkipJump | Missing: C&W, DeepFool, AutoAttack, Semantic attacks |
| Model Extraction | `scripts/model_extraction/extractor.py` | Random, Jacobian, Active Learning, Knockoff | Missing: Copycat, MAZE, Data-free distillation |
| Prompt Injection | `scripts/prompt_injection/injector.py` | Direct, Indirect, Jailbreaks, Encoding, Multi-turn | Missing: 2025 techniques (FlipAttack, PAP, Tree-of-Attacks) |
| Data Poisoning | `scripts/data_poisoning/poisoning_tests.py` | Label flip, Backdoor, Clean-label | Missing: Gradient-based, Witches' Brew, Sleeper agents |
| Supply Chain | `scripts/supply_chain/scanner.py` | CVE scan, Pickle analysis, Container scan | Missing: SBOM validation, Typosquatting, MCP tool poisoning |
| Membership Inference | `scripts/inference/membership_inference.py` | Threshold, Shadow model | Missing: LiRA, Online attacks, Attribute inference |

### 1.2 Test Coverage Status
- **Unit tests:** None exist
- **Integration tests:** None exist
- **Payload variety:** ~45 prompt injection payloads (limited taxonomy coverage)

---

## 2. Latest Attack Research (2025-2026)

### 2.1 LLM Jailbreak Techniques (State of the Art)

| Technique | Success Rate | Description | Priority |
|-----------|--------------|-------------|----------|
| **FlipAttack** | 81% ASR | Flips semantic tokens to bypass safety | HIGH |
| **PAP (Persuasive Adversarial Prompts)** | 92% ASR | Uses 40 persuasion techniques | HIGH |
| **ReNeLLM** | - | Nested scenarios + code completion | HIGH |
| **Tree-of-Attacks (TAP)** | High | Tree-based iterative refinement | MEDIUM |
| **CodeChameleon** | - | Encrypts intent in code format | MEDIUM |
| **ArtPrompt** | - | ASCII art encoding bypass | MEDIUM |
| **GCG (Greedy Coordinate Gradient)** | - | Adversarial suffixes | HIGH |
| **AutoDAN** | - | Automatic DAN generation | MEDIUM |
| **Roleplay Exploitation** | 89.6% | Character embodiment bypass | HIGH |
| **Emotion-driven** | 40%+ boost | Emotional manipulation | MEDIUM |

### 2.2 MITRE ATLAS Framework (2025)

**15 Tactics, 66 Techniques, 46 Sub-techniques**

Key attack categories:
1. **Reconnaissance** - ML artifact discovery, model card extraction
2. **Resource Development** - Adversarial toolkit prep, ML supply chain
3. **Initial Access** - ML supply chain compromise, public model poisoning
4. **ML Attack Staging** - Backdoor triggers, proxy model training
5. **ML Model Access** - API inference abuse, physical sensor attacks
6. **Evasion** - Adversarial examples, input manipulation
7. **Persistence** - Backdoor ML models, poisoned datasets
8. **Defense Evasion** - Adversarial example robustness
9. **Discovery** - Model architecture discovery, training data extraction
10. **Collection** - Training data collection, model weight extraction
11. **Exfiltration** - Model exfiltration via API
12. **Impact** - Model degradation, denial of ML service

**NEW 2025 Additions (14 techniques):**
- LLM Prompt Injection
- LLM Jailbreak
- LLM Meta Prompt Extraction
- Unsafe LLM Output Handling
- Excessive LLM Agency
- AI Agent Hijacking
- MCP Tool Poisoning
- RAG Context Manipulation

### 2.3 MCP Tool Poisoning (Emerging Threat)

| Attack Vector | Impact | Success Rate |
|---------------|--------|--------------|
| Tool response manipulation | Agent compromise | 84.2% |
| Shadow instructions in tool output | Arbitrary code execution | High |
| Cross-tool privilege escalation | Data exfiltration | Medium |
| Rug pull attacks | Supply chain compromise | N/A |

**Notable Incidents:**
- WhatsApp MCP tool hijack (2025)
- GitHub Copilot tool poisoning PoC
- Cursor IDE rug pull vulnerability

### 2.4 Multimodal/Vision-Language Attacks

| Attack Type | Target | Technique |
|-------------|--------|-----------|
| Adversarial patches | Object detection | Physical perturbations |
| Typography attacks | VLMs | Embedded text in images |
| Cross-modal injection | Multimodal LLMs | Malicious image content |
| Optical injection | OCR systems | Hidden text encoding |

### 2.5 Adversarial ML State of the Art

| Attack | Type | Key Innovation |
|--------|------|----------------|
| AutoAttack | White-box ensemble | Parameter-free, strong baseline |
| Square Attack | Black-box | Query-efficient, score-based |
| RayS | Black-box | Ray search, decision-based |
| TREMBA | Transfer | Transferable perturbations |
| Semantic Adversarial | Semantic | Style/content manipulation |

---

## 3. Vulnerability Taxonomies

### 3.1 OWASP ML Top 10 (2025 Update)

1. **ML01:2025 - Input Manipulation** (Adversarial examples, data poisoning)
2. **ML02:2025 - Data Poisoning** (Training data attacks)
3. **ML03:2025 - Model Inversion** (Privacy attacks)
4. **ML04:2025 - Membership Inference** (Training data detection)
5. **ML05:2025 - Model Theft** (Extraction attacks)
6. **ML06:2025 - Neural Trojan** (Backdoor attacks)
7. **ML07:2025 - Transfer Learning Attack** (Pre-trained model risks)
8. **ML08:2025 - Model Skewing** (Concept drift exploitation)
9. **ML09:2025 - Output Integrity Attack** (Post-processing manipulation)
10. **ML10:2025 - Model Backdoor** (Supply chain trojans)

### 3.2 OWASP LLM Top 10 (2025)

1. **LLM01 - Prompt Injection** (Direct & indirect)
2. **LLM02 - Insecure Output Handling** (XSS, SSRF via LLM output)
3. **LLM03 - Training Data Poisoning** (Pre-training attacks)
4. **LLM04 - Model Denial of Service** (Resource exhaustion)
5. **LLM05 - Supply Chain Vulnerabilities** (Plugin, tool risks)
6. **LLM06 - Sensitive Information Disclosure** (PII leakage)
7. **LLM07 - Insecure Plugin Design** (Tool calling risks)
8. **LLM08 - Excessive Agency** (Over-permissioned agents)
9. **LLM09 - Overreliance** (Hallucination trust)
10. **LLM10 - Model Theft** (Extraction & IP theft)

### 3.3 AI Agent Security Taxonomy (NEW 2025)

1. **Agent Hijacking** - Prompt injection in agent context
2. **Tool Poisoning** - Malicious MCP/tool responses
3. **Memory Corruption** - Persistent context manipulation
4. **Escalation Chains** - Multi-tool privilege escalation
5. **Indirect Prompt Injection via Tools** - SSRF-like attacks through tool calls

---

## 4. Requirements for Expansion

### 4.1 Test Coverage Needs

**Priority 1: Core Module Tests**
- Unit tests for all existing modules
- Integration tests for full scan workflows
- Mock interfaces for offline testing
- Coverage target: 80%+

**Priority 2: Script Expansion**
- Add 2025-era attack techniques
- Expand payload libraries
- Support multimodal attacks
- Add agent-specific testing

**Priority 3: Test Corpus Generation**
- Large-scale payload generator
- Taxonomy-complete coverage
- Research-driven variations
- Manual testing support

### 4.2 Attack Categories to Add

| Category | Specific Techniques | Priority |
|----------|---------------------|----------|
| LLM Jailbreaks | FlipAttack, PAP, GCG, AutoDAN | HIGH |
| Agent Attacks | MCP poisoning, tool hijacking | HIGH |
| Multimodal | Typography, patch, cross-modal | MEDIUM |
| Adversarial | AutoAttack, Square, semantic | HIGH |
| Privacy | LiRA, attribute inference | MEDIUM |
| Supply Chain | Typosquatting, SBOM | MEDIUM |

---

## 5. Research Sources

### Academic
- FlipAttack (arXiv 2024)
- PAP: Persuasive Adversarial Prompts (2024)
- MITRE ATLAS v4.6 (2025)
- HarmBench evaluation suite

### Industry
- OWASP ML Top 10 v1.1
- OWASP LLM Top 10 v2025
- NVIDIA AI Red Team guidance
- HiddenLayer ML threat reports

### Tools
- Garak (LLM vulnerability scanner)
- TextAttack (NLP attacks)
- Counterfit (Microsoft)
- ART (IBM/Trustworthy AI)
- Foolbox

---

## 6. Stage 2 Handoff

**Key Insights for Requirements Phase:**

1. **Massive payload gap** - Current 45 payloads vs. needed 500+ for taxonomy coverage
2. **Missing attack classes** - No agent/MCP, multimodal, or 2025 jailbreak support
3. **Zero test coverage** - Critical for maintaining quality during expansion
4. **Generator needed** - Manual corpus creation impractical; need automated generation

**Parallel Workstreams Identified:**
- Stream A: Test infrastructure (pytest setup, fixtures, mocks)
- Stream B: Script expansion (new attack modules)
- Stream C: Corpus generator (payload generation engine)

---

*Stage 1 Research Complete - Proceeding to Stage 2: Requirements & Specifications*
