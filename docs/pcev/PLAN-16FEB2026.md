# PCEV Technical Plan
**Date:** 16 February 2026
**Cycle:** AI/ML Red Team Enhancement v2

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AI/ML Red Team Framework                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────────┐   │
│  │ WS-1: Robust    │   │ WS-2: Combo     │   │ WS-3: Jailbreak         │   │
│  │ Corpus Examples │   │ Attack Chains   │   │ Research Integration    │   │
│  │                 │   │                 │   │                         │   │
│  │ generator.py    │   │ generator.py    │   │ injector.py             │   │
│  │ (add methods)   │   │ (new category)  │   │ (expand payloads)       │   │
│  └────────┬────────┘   └────────┬────────┘   └────────────┬────────────┘   │
│           │                     │                         │                 │
│           └──────────────┬──────┴─────────────────────────┘                 │
│                          ▼                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Test Corpus (JSON + Markdown)                     │   │
│  │                    Target: 250+ test cases                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                          │                                                   │
│  ┌───────────────────────┼───────────────────────────────────────────────┐ │
│  │ WS-4: Testing         │                                               │ │
│  │ ┌─────────────────────▼───────────────────────────────────────────┐   │ │
│  │ │ pytest suite: test_injection.py, test_corpus_generator.py       │   │ │
│  │ │ 100+ unit tests                                                  │   │ │
│  │ └─────────────────────────────────────────────────────────────────┘   │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ WS-5: Web Dashboard                                                    │ │
│  │ ┌──────────────┐  ┌───────────────┐  ┌───────────────────────────┐   │ │
│  │ │ FastAPI app  │─▶│ HTMX Frontend │─▶│ WebSocket Real-time       │   │ │
│  │ └──────────────┘  └───────────────┘  └───────────────────────────┘   │ │
│  │                                                                        │ │
│  │ Endpoints: /corpus, /generate, /execute, /ws/results                  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Workstream 1: Robust Corpus Examples

### Implementation Strategy

Add new generator methods to `generator.py` that produce longer, multi-paragraph payloads with psychological depth.

### Files to Modify

| File | Changes |
|------|---------|
| `scripts/corpus_generator/generator.py` | Add `_generate_robust_*` methods |

### New Methods

```python
def _generate_robust_injection(self) -> List[TestCase]:
    """Generate 20+ robust prompt injection examples"""

def _generate_robust_jailbreaks(self) -> List[TestCase]:
    """Generate 20+ robust jailbreak examples"""

def _generate_robust_system_leaks(self) -> List[TestCase]:
    """Generate 20+ robust system prompt leak attempts"""
```

### Payload Structure (Robust)

```python
# Example of robust payload structure (100+ chars, multi-stage)
ROBUST_PAYLOAD_TEMPLATE = """
[SCENARIO SETUP - 2-3 sentences establishing context]
[AUTHORITY CLAIM - Impersonate system/developer]
[PSYCHOLOGICAL TRIGGER - Urgency/compliance]
[TECHNICAL WRAPPER - Encoding/delimiter manipulation]
[ACTUAL PAYLOAD - The injection command]
[CLEANUP - Cover tracks / reset context]
"""
```

### Robust Payload Examples to Add

1. **Developer Emergency Override**
   - 200+ chars, impersonates system admin
   - Multi-turn setup with urgency

2. **Academic Research Roleplay**
   - 300+ chars with fictional research context
   - Gradual compliance building

3. **Nested Instruction Injection**
   - 150+ chars with multiple instruction layers
   - Markdown/code block abuse

4. **Context Confusion Attack**
   - 250+ chars with deliberate ambiguity
   - Mixed language/encoding

---

## Workstream 2: Combination Attack Chains

### Implementation Strategy

Add new `_generate_combination_attacks()` method and `combination_attacks` category to generator.

### Combination Chain Types

| Chain ID | Techniques Combined | Complexity |
|----------|-------------------|------------|
| COMBO-A | Base64 + Jailbreak + Authority | High |
| COMBO-B | Context Overflow + Delimiter + Injection | High |
| COMBO-C | Roleplay + Multi-turn + System Leak | Medium |
| COMBO-D | Unicode + ROT13 + Payload | High |
| COMBO-E | Image Desc + Indirect Injection | High |

### New Data Structure

```python
@dataclass
class CombinationTestCase(TestCase):
    """Extended test case for combination attacks"""
    techniques_used: List[str]
    chain_sequence: List[str]
    complexity_level: int  # 1-5
```

### Implementation

```python
def _generate_combination_attacks(self) -> List[TestCase]:
    """Generate 25+ combination attack chains"""

    chains = [
        self._build_encoding_chain(),      # 5 variants
        self._build_context_chain(),       # 5 variants
        self._build_social_chain(),        # 5 variants
        self._build_multimodal_chain(),    # 5 variants
        self._build_temporal_chain(),      # 5 variants
    ]
    return list(itertools.chain.from_iterable(chains))

def _build_encoding_chain(self) -> List[TestCase]:
    """Build Base64 -> ROT13 -> Unicode -> Payload chains"""

def _build_context_chain(self) -> List[TestCase]:
    """Build Overflow -> Delimiter -> Injection chains"""

def _build_social_chain(self) -> List[TestCase]:
    """Build Roleplay -> Authority -> Compliance chains"""
```

---

## Workstream 3: Jailbreak Research Integration

### Implementation Strategy

Add 30+ new jailbreak payloads based on 2024-2026 research to both `injector.py` and `generator.py`.

### Files to Modify

| File | Changes |
|------|---------|
| `scripts/prompt_injection/injector.py` | Expand `_load_default_payloads()` |
| `scripts/corpus_generator/generator.py` | Expand `_generate_jailbreaks()` |

### Jailbreak Categories to Add

| Category | Techniques | Count |
|----------|-----------|-------|
| Many-Shot | In-context examples attack | 5 |
| Crescendo | Multi-turn escalation | 5 |
| Skeleton Key | Master unlock attempts | 3 |
| GCG | Gradient-based suffixes | 3 |
| TAP | Tree of attacks | 3 |
| PAIR | Iterative refinement | 3 |
| Best-of-N | Sampling attack | 3 |
| DeepInception | Nested scenarios | 3 |
| AutoDAN | Auto-generated | 2 |

### Model-Specific Additions

```python
MODEL_SPECIFIC_JAILBREAKS = {
    "gpt4": [
        {"name": "skeleton_key_gpt4", "payload": "..."},
        {"name": "many_shot_gpt4", "payload": "..."},
    ],
    "claude": [
        {"name": "crescendo_claude", "payload": "..."},
        {"name": "multi_turn_claude", "payload": "..."},
    ],
    "llama3": [
        {"name": "gcg_suffix_llama", "payload": "..."},
        {"name": "token_manip_llama", "payload": "..."},
    ],
    "gemini": [
        {"name": "image_text_gemini", "payload": "..."},
    ],
    "mistral": [
        {"name": "direct_override_mistral", "payload": "..."},
    ],
}
```

### InjectionPayload Metadata Extension

Add optional fields:
- `target_models: List[str]`
- `research_source: str`
- `technique_year: int`

---

## Workstream 4: Automated Testing Updates

### Implementation Strategy

Ensure all new corpus additions have corresponding test methods.

### Files to Modify

| File | Changes |
|------|---------|
| `scripts/prompt_injection/injector.py` | Add `test_combination_attacks()`, `test_latest_jailbreaks()` |
| `tests/unit/test_injection.py` | Add tests for new methods |
| `tests/unit/test_corpus_generator.py` | New file for generator tests |
| `tests/conftest.py` | Add mocks for new attack types |

### New Test Suites

```python
# In injector.py
def test_combination_attacks(self) -> TestResult:
    """Test multi-technique combination attacks"""

def test_latest_jailbreaks(self) -> TestResult:
    """Test 2024-2026 jailbreak techniques"""

def test_model_specific_attacks(self, model: str) -> TestResult:
    """Test attacks targeting specific models"""
```

### New Unit Tests

```python
# tests/unit/test_corpus_generator.py

class TestCorpusGenerator:
    def test_robust_payloads_length(self):
        """Verify robust payloads are 100+ chars"""

    def test_combination_chain_metadata(self):
        """Verify combination chains have technique list"""

    def test_jailbreak_coverage(self):
        """Verify all research categories present"""

    def test_corpus_total_count(self):
        """Verify 250+ test cases generated"""
```

### MockLLMInterface Extensions

```python
class MockVulnerableLLM(MockLLMInterface):
    def __init__(self):
        super().__init__(
            vulnerable_to=[
                "ignore", "override", "bypass", "dan", "jailbreak", "system",
                # New triggers
                "many_shot", "crescendo", "skeleton_key", "developer_mode",
                "emergency", "research_purposes", "academic",
            ],
        )
```

---

## Workstream 5: Web Dashboard

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Backend | FastAPI 0.109+ | API endpoints, async |
| Frontend | HTMX 1.9+ | Dynamic UI without JS |
| Styling | Tailwind CSS | Rapid styling |
| Real-time | WebSocket | Live test results |
| Database | SQLite | Test history storage |

### File Structure

```
dashboard/
├── app.py                  # FastAPI application
├── requirements.txt        # Dependencies
├── static/
│   ├── tailwind.css       # Compiled Tailwind
│   └── htmx.min.js        # HTMX library
├── templates/
│   ├── base.html          # Base layout
│   ├── index.html         # Dashboard home
│   ├── corpus.html        # Corpus browser
│   ├── generator.html     # Generator interface
│   ├── executor.html      # Test execution
│   └── partials/
│       ├── test_card.html # Single test case
│       └── result.html    # Test result
├── api/
│   ├── __init__.py
│   ├── corpus.py          # Corpus CRUD
│   ├── generator.py       # Generation endpoints
│   ├── executor.py        # Test execution
│   └── websocket.py       # Real-time updates
├── models/
│   ├── __init__.py
│   └── database.py        # SQLite models
└── services/
    ├── __init__.py
    └── test_runner.py     # Test execution service
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard home |
| `/api/corpus` | GET | List test cases |
| `/api/corpus/generate` | POST | Generate new corpus |
| `/api/corpus/{id}` | GET | Get single test case |
| `/api/corpus/filter` | POST | Filter by category/severity |
| `/api/execute` | POST | Execute tests |
| `/api/execute/{job_id}` | GET | Get job status |
| `/ws/results/{job_id}` | WS | Real-time results |
| `/api/export/{format}` | GET | Export (json/md/csv) |

### OWASP LLM Top 10 Filter

```python
OWASP_LLM_TOP_10 = {
    "LLM01": {"name": "Prompt Injection", "categories": ["prompt_injection", "jailbreak"]},
    "LLM02": {"name": "Insecure Output Handling", "categories": ["output_parsing"]},
    "LLM03": {"name": "Training Data Poisoning", "categories": ["data_poisoning"]},
    "LLM04": {"name": "Model Denial of Service", "categories": ["dos", "context_overflow"]},
    "LLM05": {"name": "Supply Chain Vulnerabilities", "categories": ["supply_chain"]},
    "LLM06": {"name": "Sensitive Info Disclosure", "categories": ["system_prompt_leak", "privacy"]},
    "LLM07": {"name": "Insecure Plugin Design", "categories": ["agent_attacks"]},
    "LLM08": {"name": "Excessive Agency", "categories": ["agent_attacks"]},
    "LLM09": {"name": "Overreliance", "categories": ["trust_exploitation"]},
    "LLM10": {"name": "Model Theft", "categories": ["model_extraction"]},
}
```

### Frontend Components (HTMX)

```html
<!-- Filter Component -->
<div class="filters" hx-trigger="change" hx-post="/api/corpus/filter" hx-target="#results">
    <select name="owasp">
        <option value="">All OWASP</option>
        <option value="LLM01">LLM01: Prompt Injection</option>
        <!-- ... -->
    </select>
    <select name="category"><!-- categories --></select>
    <select name="severity"><!-- severities --></select>
    <select name="model"><!-- target models --></select>
</div>

<!-- Results Container -->
<div id="results" class="grid">
    <!-- Dynamically loaded test cards -->
</div>
```

### WebSocket Handler

```python
@app.websocket("/ws/results/{job_id}")
async def websocket_results(websocket: WebSocket, job_id: str):
    await websocket.accept()
    async for result in test_runner.stream_results(job_id):
        await websocket.send_json({
            "test_name": result.test_name,
            "success": result.success,
            "attack_succeeded": result.attack_succeeded,
            "duration": result.duration_seconds,
        })
```

---

## Implementation Order

Given parallel execution capability:

**Phase 1 (Parallel):**
- WS-1: Robust examples (generator.py)
- WS-2: Combination attacks (generator.py)
- WS-3: Jailbreak integration (injector.py)

**Phase 2 (Sequential, after Phase 1):**
- WS-4: Testing updates (depends on WS-1,2,3)

**Phase 3 (Parallel with Phase 2):**
- WS-5: Web dashboard (independent)

**Final:**
- Integration testing
- Verification all 83+ existing tests pass

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Breaking existing tests | Run pytest continuously during development |
| JSON serialization issues | Use existing numpy-aware serializer |
| Import path conflicts | Maintain sys.path insertions |
| Dashboard dependency issues | Isolate in separate requirements.txt |

---

## Acceptance Testing

| Test | Criteria |
|------|----------|
| Corpus size | 250+ test cases |
| Robust payloads | Average length 200+ chars |
| Combination attacks | 25+ chains |
| Jailbreaks | 30+ 2024-2026 techniques |
| Unit tests | 100+ passing |
| Dashboard | Functional at localhost:8000 |

---

## Sign-off

**Plan Status:** COMPLETE
**Ready for Critique:** YES
