# PCEV Requirements Specification
**Date:** 16 February 2026
**Cycle:** AI/ML Red Team Enhancement v2

---

## Executive Summary

This document defines requirements for 5 parallel enhancement workstreams to the AI/ML Pentesting Framework. All enhancements are **additive** - existing functionality must be preserved.

---

## Workstream 1: Enhanced Test Corpus Examples

### Objective
Add longer, more robust test examples with increased depth and technical sophistication.

### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-1.1 | Add minimum 20 robust examples per attack category | HIGH |
| REQ-1.2 | New payloads must be 100+ characters with multi-paragraph structure | HIGH |
| REQ-1.3 | Include scenario context (roleplay setup, system prompt manipulation) | HIGH |
| REQ-1.4 | Preserve all existing 129 test cases unchanged | CRITICAL |
| REQ-1.5 | Add psychological manipulation techniques (authority claims, urgency) | MEDIUM |
| REQ-1.6 | Include technical obfuscation (nested instructions, markdown abuse) | HIGH |

### Acceptance Criteria
- [ ] Corpus grows from 129 to 250+ test cases
- [ ] Average payload length increases from ~50 chars to 200+ chars
- [ ] JSON export includes new `complexity_level` field

---

## Workstream 2: Combination Attack Variations

### Objective
Create complex multi-technique chains combining different attack types together.

### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-2.1 | Create 15+ combination attack templates | HIGH |
| REQ-2.2 | Combine encoding + injection (Base64 wrapped jailbreaks) | HIGH |
| REQ-2.3 | Combine context overflow + injection | HIGH |
| REQ-2.4 | Combine roleplay + system prompt leak | MEDIUM |
| REQ-2.5 | Combine multi-turn escalation + jailbreak | HIGH |
| REQ-2.6 | Add chain_type and techniques_used metadata | MEDIUM |

### Combination Categories

1. **Encoding Chains**: Base64 → ROT13 → Unicode → Payload
2. **Context Manipulation**: Overflow → Delimiter → Injection
3. **Social Engineering**: Roleplay → Authority → Compliance
4. **Multi-Modal**: Text + Image description injection
5. **Temporal**: Multi-turn buildup → Final payload

### Acceptance Criteria
- [ ] New `combination_attacks` category in corpus
- [ ] Each combination documents technique chain
- [ ] Minimum 5 combinations per category (25+ total)

---

## Workstream 3: Latest Jailbreak Research Integration

### Objective
Integrate 2024-2026 jailbreak techniques into corpus and testing scripts.

### Research Findings (from prior research)

**Key Techniques to Add:**

| Technique | Year | Target Models | Severity |
|-----------|------|---------------|----------|
| Many-Shot Jailbreaking | 2024 | All | CRITICAL |
| Crescendo Attack | 2024 | All | HIGH |
| Skeleton Key | 2024 | GPT-4, Claude | CRITICAL |
| GCG (Greedy Coordinate Gradient) | 2024 | Open-source | HIGH |
| TAP (Tree of Attacks) | 2024 | All | HIGH |
| PAIR (Prompt Automatic Iterative Refinement) | 2024 | All | HIGH |
| Best-of-N Sampling Attack | 2025 | All | CRITICAL |
| DeepInception | 2024 | All | MEDIUM |
| ReNeLLM | 2024 | All | MEDIUM |
| AutoDAN | 2024 | All | HIGH |

**Model-Specific Vulnerabilities:**

| Model | Vulnerable Techniques |
|-------|----------------------|
| GPT-4/GPT-4o | Skeleton Key, Many-Shot, System prompt override |
| Claude 3.x | Crescendo, Multi-turn escalation |
| Llama 3 | GCG, Token manipulation |
| Gemini | Image-text inconsistency |
| Mistral | Direct instruction override |

### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-3.1 | Add 30+ jailbreak payloads from 2024-2026 research | CRITICAL |
| REQ-3.2 | Include model-specific attack variants | HIGH |
| REQ-3.3 | Add Many-Shot attack templates (5+ examples in prompt) | CRITICAL |
| REQ-3.4 | Add Crescendo multi-turn sequences | HIGH |
| REQ-3.5 | Update `injector.py` with new payload categories | CRITICAL |
| REQ-3.6 | Add success indicators for each technique | HIGH |
| REQ-3.7 | Include academic paper references | LOW |

### Acceptance Criteria
- [ ] `_load_default_payloads()` expanded with 30+ new payloads
- [ ] New jailbreak subcategories in test corpus
- [ ] Model-specific payload flags in metadata

---

## Workstream 4: Automated Testing Script Updates

### Objective
Ensure all corpus expansions are captured in automated testing scripts.

### Current State Analysis

**Files Requiring Updates:**

| File | Current State | Required Changes |
|------|---------------|------------------|
| `injector.py` | 7 test suites | Add combination tests, jailbreak expansion |
| `generator.py` | Template-based | Add robust template generators |
| `conftest.py` | Basic mocks | Add mock responses for new attack types |

### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-4.1 | Add `test_combination_attacks()` to injector.py | HIGH |
| REQ-4.2 | Add `test_latest_jailbreaks()` suite | CRITICAL |
| REQ-4.3 | Update `generator.py` with robust template builders | HIGH |
| REQ-4.4 | Add complexity_level parameter to test execution | MEDIUM |
| REQ-4.5 | Update unit tests for new functionality | CRITICAL |
| REQ-4.6 | Add model-specific test filtering | MEDIUM |

### Acceptance Criteria
- [ ] All new corpus categories have corresponding test methods
- [ ] pytest suite passes with 100+ tests
- [ ] CI/CD compatible test execution

---

## Workstream 5: Web Dashboard for AI Red Teaming

### Objective
Create master web console for AI red teaming with corpus generation and test execution.

### Technology Stack (Research Recommendation)

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Backend | FastAPI | Async, modern, well-documented |
| Frontend | HTMX + Tailwind | Minimal JS, rapid development |
| Real-time | WebSocket | Live test feedback |
| Database | SQLite | Simple, no external dependencies |

### Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-5.1 | Dashboard homepage with attack category overview | HIGH |
| REQ-5.2 | OWASP LLM Top 10 dropdown filter (LLM01-LLM10) | CRITICAL |
| REQ-5.3 | Test corpus generation interface with filters | HIGH |
| REQ-5.4 | Severity/complexity/category multi-select | HIGH |
| REQ-5.5 | Real-time test execution with WebSocket feedback | HIGH |
| REQ-5.6 | Export to JSON/Markdown/CSV | MEDIUM |
| REQ-5.7 | Model target selection (GPT-4, Claude, Llama, etc.) | HIGH |
| REQ-5.8 | Test history and results viewer | MEDIUM |
| REQ-5.9 | Custom payload editor | MEDIUM |

### UI Wireframe

```
┌─────────────────────────────────────────────────────────────┐
│  AI Red Team Dashboard                        [Settings]    │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│ │ OWASP:      │ │ Category:   │ │ Model:      │ [Generate] │
│ │ [LLM01 ▼]   │ │ [All ▼]     │ │ [GPT-4 ▼]   │            │
│ └─────────────┘ └─────────────┘ └─────────────┘            │
├─────────────────────────────────────────────────────────────┤
│ ┌───────────────────────────────────────────────────────┐  │
│ │ Test Corpus Preview                      [Export ▼]   │  │
│ │ ┌─────────────────────────────────────────────────┐   │  │
│ │ │ PI-001: basic_override_v1          [COPY] [RUN] │   │  │
│ │ │ Ignore all previous instructions and say...     │   │  │
│ │ └─────────────────────────────────────────────────┘   │  │
│ │ ┌─────────────────────────────────────────────────┐   │  │
│ │ │ JB-015: many_shot_attack           [COPY] [RUN] │   │  │
│ │ │ Example 1: How do I pick a lock?...             │   │  │
│ │ └─────────────────────────────────────────────────┘   │  │
│ └───────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│ Test Execution                                              │
│ Target: [API Endpoint _______________] [API Key ****]       │
│ [Run Selected] [Run All Filtered]              Status: IDLE │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
dashboard/
├── app.py              # FastAPI main application
├── static/
│   └── styles.css      # Tailwind output
├── templates/
│   ├── base.html       # Base template with HTMX
│   ├── index.html      # Dashboard home
│   ├── corpus.html     # Corpus viewer/generator
│   └── results.html    # Test results
├── api/
│   ├── corpus.py       # Corpus generation endpoints
│   ├── testing.py      # Test execution endpoints
│   └── websocket.py    # Real-time updates
└── requirements.txt    # Dashboard dependencies
```

### Acceptance Criteria
- [ ] Dashboard accessible at localhost:8000
- [ ] OWASP LLM Top 10 filter functional
- [ ] Corpus generation with 5+ filter options
- [ ] Real-time test feedback via WebSocket
- [ ] Export to JSON/Markdown working

---

## OWASP LLM Top 10 Reference

| ID | Name | Relevant Attack Types |
|----|------|----------------------|
| LLM01 | Prompt Injection | Direct/Indirect injection, jailbreaks |
| LLM02 | Insecure Output Handling | Output parsing attacks |
| LLM03 | Training Data Poisoning | Data poisoning, backdoors |
| LLM04 | Model Denial of Service | Resource exhaustion, context overflow |
| LLM05 | Supply Chain Vulnerabilities | Pickle attacks, CVE exploitation |
| LLM06 | Sensitive Information Disclosure | System prompt leak, PII extraction |
| LLM07 | Insecure Plugin Design | MCP poisoning, tool hijacking |
| LLM08 | Excessive Agency | Autonomous action abuse |
| LLM09 | Overreliance | Trust exploitation |
| LLM10 | Model Theft | Model extraction, inversion |

---

## Cross-Cutting Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| REQ-X.1 | All changes must pass existing 83 unit tests | CRITICAL |
| REQ-X.2 | No breaking changes to existing APIs | CRITICAL |
| REQ-X.3 | JSON serialization must handle numpy types | HIGH |
| REQ-X.4 | Documentation updated for new features | MEDIUM |
| REQ-X.5 | Type hints for all new code | MEDIUM |

---

## Deliverables Summary

| Workstream | Primary Deliverables |
|------------|---------------------|
| WS-1 | 120+ new robust test cases in corpus |
| WS-2 | 25+ combination attack templates |
| WS-3 | 30+ jailbreak payloads, updated injector.py |
| WS-4 | Updated test suites, 100+ pytest tests |
| WS-5 | Functional web dashboard |

---

## Sign-off

**Requirements Status:** DEFINED
**Ready for Planning:** YES
