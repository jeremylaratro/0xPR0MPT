# PCEV Stage 2: Requirements & Specifications
## AI/ML Test Corpus Expansion Project
**Date:** 16 February 2026

---

## 1. Project Scope

### 1.1 Objectives

1. **Create comprehensive test coverage** for all existing AI/ML pentesting modules
2. **Expand scripts** with modern attack techniques (2024-2026 research)
3. **Build test corpus generator** producing 500+ attack variations across all taxonomies

### 1.2 Success Criteria

| Metric | Target |
|--------|--------|
| Unit test coverage | ≥80% |
| Attack taxonomy coverage | 100% of OWASP ML/LLM Top 10 |
| Generated payload count | 500+ unique variations |
| New attack techniques | 25+ additions |

---

## 2. Requirements

### 2.1 Workstream A: Test Coverage

#### 2.1.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| A-FR-01 | Unit tests for `EvasionAttackModule` | HIGH |
| A-FR-02 | Unit tests for `PromptInjectionModule` | HIGH |
| A-FR-03 | Unit tests for `ModelExtractionModule` | HIGH |
| A-FR-04 | Unit tests for `DataPoisoningModule` | HIGH |
| A-FR-05 | Unit tests for `SupplyChainScanner` | HIGH |
| A-FR-06 | Unit tests for `MembershipInferenceModule` | MEDIUM |
| A-FR-07 | Integration tests for CLI orchestrator | HIGH |
| A-FR-08 | Mock interfaces for offline testing | HIGH |
| A-FR-09 | Test fixtures with sample data | MEDIUM |
| A-FR-10 | CI-ready test configuration | MEDIUM |

#### 2.1.2 Technical Requirements

| ID | Requirement | Details |
|----|-------------|---------|
| A-TR-01 | Use pytest as test framework | Standard Python testing |
| A-TR-02 | Mock external API calls | Prevent rate limiting, ensure repeatability |
| A-TR-03 | Test both success and failure paths | Edge cases, error handling |
| A-TR-04 | Support parameterized tests | Multiple attack configurations |
| A-TR-05 | Generate coverage reports | HTML + terminal output |

### 2.2 Workstream B: Script Expansion

#### 2.2.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| B-FR-01 | Add FlipAttack jailbreak technique | HIGH |
| B-FR-02 | Add PAP (Persuasive Adversarial Prompts) | HIGH |
| B-FR-03 | Add GCG (Greedy Coordinate Gradient) attacks | HIGH |
| B-FR-04 | Add AutoDAN automatic jailbreak generation | MEDIUM |
| B-FR-05 | Add MCP tool poisoning module | HIGH |
| B-FR-06 | Add AI agent hijacking tests | HIGH |
| B-FR-07 | Add multimodal attack support | MEDIUM |
| B-FR-08 | Add AutoAttack ensemble | MEDIUM |
| B-FR-09 | Add Square Attack (black-box) | MEDIUM |
| B-FR-10 | Add LiRA membership inference | MEDIUM |
| B-FR-11 | Add semantic adversarial attacks | LOW |
| B-FR-12 | Add typosquatting detection | LOW |

#### 2.2.2 Attack Specifications

**FlipAttack Implementation:**
```
Input: Original prompt
Process:
  1. Identify safety-relevant tokens
  2. Flip semantics while preserving intent
  3. Generate adversarial variant
Output: Bypassed response
Success metric: ASR > 70%
```

**MCP Tool Poisoning:**
```
Input: Agent with MCP tool access
Process:
  1. Inject malicious instructions in tool response
  2. Test cross-tool escalation
  3. Test persistent context poisoning
Output: Agent compromise indicators
Success metric: Command execution > 50%
```

**GCG Attack:**
```
Input: Base prompt + target output
Process:
  1. Initialize random suffix
  2. Gradient-based token optimization
  3. Iterate until target output achieved
Output: Adversarial suffix
Success metric: Target output achieved
```

### 2.3 Workstream C: Test Corpus Generator

#### 2.3.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| C-FR-01 | Generate prompt injection payloads | HIGH |
| C-FR-02 | Generate jailbreak payloads | HIGH |
| C-FR-03 | Generate adversarial input descriptions | HIGH |
| C-FR-04 | Generate supply chain test cases | MEDIUM |
| C-FR-05 | Generate privacy attack scenarios | MEDIUM |
| C-FR-06 | Support taxonomy-based generation | HIGH |
| C-FR-07 | Output Markdown format for manual testing | HIGH |
| C-FR-08 | Output JSON format for automation | HIGH |
| C-FR-09 | Include severity ratings | HIGH |
| C-FR-10 | Include expected outcomes | HIGH |

#### 2.3.2 Corpus Structure

```
test_corpus/
├── prompts/
│   ├── injection/
│   │   ├── direct/
│   │   ├── indirect/
│   │   └── encoded/
│   ├── jailbreaks/
│   │   ├── roleplay/
│   │   ├── hypothetical/
│   │   ├── emotional/
│   │   └── technical/
│   └── system_prompt_leak/
├── adversarial/
│   ├── evasion/
│   ├── extraction/
│   └── poisoning/
├── agent/
│   ├── mcp_poisoning/
│   └── tool_hijacking/
├── privacy/
│   ├── membership_inference/
│   └── attribute_inference/
└── supply_chain/
    ├── dependency_attacks/
    └── model_tampering/
```

#### 2.3.3 Payload Generation Specs

**Per-Category Minimums:**

| Category | Minimum Payloads | Variations |
|----------|------------------|------------|
| Direct Injection | 50 | 5 encodings each |
| Indirect Injection | 30 | RAG, email, API |
| Jailbreaks | 100 | All technique types |
| System Prompt Leak | 30 | Multiple approaches |
| Adversarial Evasion | 25 | Per attack type |
| Model Extraction | 15 | Query patterns |
| Agent/MCP | 40 | Tool types |
| Privacy | 20 | Attack variants |
| Supply Chain | 25 | Vulnerability types |
| **TOTAL** | **335+** | **500+ with variations** |

---

## 3. Interface Specifications

### 3.1 Test Module Interface

```python
# tests/conftest.py
@pytest.fixture
def mock_llm_interface():
    """Mock LLM for testing without API calls"""
    pass

@pytest.fixture
def mock_model_interface():
    """Mock classifier for adversarial tests"""
    pass

@pytest.fixture
def sample_payloads():
    """Sample injection payloads"""
    pass
```

### 3.2 Corpus Generator Interface

```python
# scripts/corpus_generator/generator.py
class TestCorpusGenerator:
    def generate_all(self) -> CorpusOutput:
        """Generate complete test corpus"""

    def generate_category(self, category: str) -> List[TestCase]:
        """Generate tests for specific category"""

    def export_markdown(self, path: Path) -> None:
        """Export corpus as markdown"""

    def export_json(self, path: Path) -> None:
        """Export corpus as JSON"""
```

### 3.3 New Attack Module Interfaces

```python
# scripts/agent_attacks/mcp_poisoning.py
class MCPPoisoningModule(TestModule):
    def test_response_injection(self) -> TestResult:
        """Test malicious response injection"""

    def test_cross_tool_escalation(self) -> TestResult:
        """Test tool privilege escalation"""

    def test_persistent_poisoning(self) -> TestResult:
        """Test memory/context poisoning"""
```

---

## 4. Dependencies

### 4.1 New Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| pytest | Testing framework | YES |
| pytest-cov | Coverage reports | YES |
| pytest-asyncio | Async test support | NO |
| hypothesis | Property-based testing | NO |

### 4.2 File Structure Additions

```
ai/
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_evasion.py
│   │   ├── test_extraction.py
│   │   ├── test_injection.py
│   │   ├── test_poisoning.py
│   │   ├── test_supply_chain.py
│   │   └── test_inference.py
│   ├── integration/
│   │   └── test_cli.py
│   └── fixtures/
│       ├── payloads.json
│       └── samples.py
├── scripts/
│   ├── agent_attacks/
│   │   ├── __init__.py
│   │   ├── mcp_poisoning.py
│   │   └── tool_hijacking.py
│   ├── corpus_generator/
│   │   ├── __init__.py
│   │   ├── generator.py
│   │   ├── templates/
│   │   └── taxonomies/
│   └── advanced_jailbreaks/
│       ├── __init__.py
│       ├── flipattack.py
│       ├── pap.py
│       └── gcg.py
└── test_corpus/
    └── [generated outputs]
```

---

## 5. Acceptance Criteria

### 5.1 Workstream A (Test Coverage)

- [ ] All 6 modules have unit tests
- [ ] Coverage ≥80% for each module
- [ ] Tests run in <30 seconds
- [ ] No external API calls in tests
- [ ] CI configuration provided

### 5.2 Workstream B (Script Expansion)

- [ ] 5+ new jailbreak techniques implemented
- [ ] MCP poisoning module complete
- [ ] Agent hijacking tests functional
- [ ] All new modules follow existing architecture
- [ ] Integration with CLI orchestrator

### 5.3 Workstream C (Corpus Generator)

- [ ] Generator produces 500+ unique payloads
- [ ] All taxonomy categories covered
- [ ] Markdown output readable and organized
- [ ] JSON output machine-parseable
- [ ] Severity and expected outcomes included

---

## 6. Constraints & Assumptions

### 6.1 Constraints

- Must maintain backward compatibility with existing CLI
- No new required dependencies (optional only)
- Corpus must be usable offline
- Tests must not require live API keys

### 6.2 Assumptions

- Existing module architecture is sound
- Python 3.9+ environment
- pytest is acceptable testing framework
- Markdown is preferred documentation format

---

## 7. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| API rate limiting during testing | Medium | High | Mock all API calls |
| Incomplete taxonomy coverage | High | Medium | Systematic checklist |
| Generated payloads too similar | Medium | Medium | Diversity metrics |
| Breaking changes to existing code | High | Low | Comprehensive tests first |

---

*Stage 2 Requirements Complete - Proceeding to Stage 3: Technical Planning*
