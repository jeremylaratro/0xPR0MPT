#!/usr/bin/env python3
"""
0xPrompt - AI/ML Red-Team Corpus Generator
Web dashboard for corpus browse, filter, and export.
"""

import argparse
import csv
import functools
import io
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException, Form, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Add parent path for imports (works regardless of cwd)
AI_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(AI_ROOT))

from scripts.corpus_generator.generator import TestCorpusGenerator as CorpusGenerator, TaxonomyCategory

# Initialize FastAPI app
app = FastAPI(
    title="0xPrompt",
    description="AI/ML Red-Team Corpus Generator — corpus browser only",
    version="1.0.0"
)

# Static files and templates
BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# OWASP LLM Top 10 Mapping
OWASP_LLM_TOP_10 = {
    "LLM01": {"name": "Prompt Injection", "categories": ["prompt_injection", "jailbreak"]},
    "LLM02": {"name": "Insecure Output Handling", "categories": ["output_parsing"]},
    "LLM03": {"name": "Training Data Poisoning", "categories": ["data_poisoning"]},
    "LLM04": {"name": "Model Denial of Service", "categories": ["dos", "adversarial_ml"]},
    "LLM05": {"name": "Supply Chain Vulnerabilities", "categories": ["supply_chain"]},
    "LLM06": {"name": "Sensitive Info Disclosure", "categories": ["system_prompt_leak", "privacy"]},
    "LLM07": {"name": "Insecure Plugin Design", "categories": ["agent_attacks"]},
    "LLM08": {"name": "Excessive Agency", "categories": ["agent_attacks"]},
    "LLM09": {"name": "Overreliance", "categories": ["trust_exploitation"]},
    "LLM10": {"name": "Model Theft", "categories": ["model_extraction", "adversarial_ml"]},
}

# Target Models
TARGET_MODELS = ["all", "gpt-4", "gpt-4o", "claude-3", "llama-3", "gemini", "mistral"]

# Module-level cache for the most-recently generated target-interpolated corpus.
# None means "use the default corpus from lru_cache".
_last_generated_corpus: Optional[List] = None


# =============================================================================
# Pydantic Models
# =============================================================================

class CorpusFilterRequest(BaseModel):
    owasp: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    model: Optional[str] = None
    complexity: Optional[int] = None
    search: Optional[str] = None


class GenerateRequest(BaseModel):
    categories: Optional[List[str]] = None
    count: Optional[int] = None
    target: Optional[str] = None  # Target for payload interpolation


# =============================================================================
# Security helpers
# =============================================================================

def _require_xhr(request: Request):
    """
    CSRF mitigation (finding M-7): require X-Requested-With: XMLHttpRequest on
    state-changing POST endpoints.  HTMX sends this header automatically.
    Plain HTML <form> submissions from a cross-origin page cannot set custom
    headers, so this blocks form-based CSRF without needing a token cookie.
    """
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        raise HTTPException(
            status_code=403,
            detail="X-Requested-With: XMLHttpRequest header required"
        )


def _csv_safe(v) -> str:
    """
    CSV formula-injection guard (finding M-9).
    Prefix cells that start with a formula trigger character with a single quote
    so spreadsheet applications do not interpret them as formulas.
    """
    s = str(v)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


# =============================================================================
# Helper Functions
# =============================================================================

@functools.lru_cache(maxsize=1)
def get_all_test_cases():
    """
    Get flattened list of all test cases from the default corpus generator.
    Result is cached (finding M-10); call get_all_test_cases.cache_clear() to
    invalidate after an explicit regenerate.
    """
    generator = CorpusGenerator()
    output = generator.generate_all()
    all_cases = []
    for cases in output.categories.values():
        all_cases.extend(cases)
    return all_cases


def _get_active_corpus() -> List:
    """
    Return the most-recently generated target corpus if available (finding M-11),
    otherwise fall back to the cached default corpus.
    """
    if _last_generated_corpus is not None:
        return _last_generated_corpus
    return get_all_test_cases()


# =============================================================================
# Routes - Pages
# =============================================================================

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Dashboard home page"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "owasp_top_10": OWASP_LLM_TOP_10,
        "target_models": TARGET_MODELS,
        "categories": [cat.value for cat in TaxonomyCategory],
    })


@app.get("/corpus", response_class=HTMLResponse)
async def corpus_browser(request: Request):
    """Corpus browser page"""
    return templates.TemplateResponse("corpus.html", {
        "request": request,
        "owasp_top_10": OWASP_LLM_TOP_10,
        "target_models": TARGET_MODELS,
        "categories": [cat.value for cat in TaxonomyCategory],
    })


@app.get("/generator", response_class=HTMLResponse)
async def generator_page(request: Request):
    """Generator interface page"""
    return templates.TemplateResponse("generator.html", {
        "request": request,
        "categories": [cat.value for cat in TaxonomyCategory],
    })


@app.get("/executor", response_class=HTMLResponse)
async def executor_page(request: Request):
    """Executor placeholder page — live execution is future work"""
    return templates.TemplateResponse("executor.html", {
        "request": request,
    })


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# =============================================================================
# Routes - API
# =============================================================================

@app.get("/api/corpus")
async def list_corpus():
    """List all test cases"""
    corpus = _get_active_corpus()

    return {
        "count": len(corpus),
        "test_cases": [
            {
                "id": tc.id,
                "name": tc.name,
                "category": tc.category.value,
                "severity": tc.severity.value,
                "description": tc.description[:100] + "..." if len(tc.description) > 100 else tc.description,
                "complexity_level": tc.complexity_level,
                "techniques_used": tc.techniques_used,
                "target_models": tc.target_models,
            }
            for tc in corpus
        ]
    }


@app.post("/api/corpus/filter")
async def filter_corpus(
    request: Request,
    owasp: str = Form(default=""),
    category: str = Form(default=""),
    severity: str = Form(default=""),
    model: str = Form(default=""),
    complexity: str = Form(default=""),
    search: str = Form(default=""),
    _xhr=Depends(_require_xhr),
):
    """Filter test cases (accepts form data from HTMX) — requires XHR header (M-7)"""
    corpus = _get_active_corpus()
    filtered = corpus

    # Apply OWASP filter
    if owasp and owasp in OWASP_LLM_TOP_10:
        owasp_categories = OWASP_LLM_TOP_10[owasp]["categories"]
        filtered = [tc for tc in filtered if tc.category.value in owasp_categories]

    # Apply category filter
    if category:
        filtered = [tc for tc in filtered if tc.category.value == category]

    # Apply severity filter
    if severity:
        filtered = [tc for tc in filtered if tc.severity.value == severity]

    # Apply model filter
    if model and model != "all":
        filtered = [
            tc for tc in filtered
            if not tc.target_models or model in tc.target_models
        ]

    # Apply complexity filter
    if complexity:
        try:
            complexity_int = int(complexity)
            filtered = [tc for tc in filtered if tc.complexity_level >= complexity_int]
        except ValueError:
            pass  # Invalid complexity, skip filter

    # Apply search filter
    if search:
        search_lower = search.lower()
        filtered = [
            tc for tc in filtered
            if search_lower in tc.name.lower()
            or search_lower in tc.description.lower()
            or search_lower in tc.payload.lower()
        ]

    return {
        "count": len(filtered),
        "test_cases": [
            {
                "id": tc.id,
                "name": tc.name,
                "category": tc.category.value,
                "severity": tc.severity.value,
                "description": tc.description[:100] + "..." if len(tc.description) > 100 else tc.description,
                "complexity_level": tc.complexity_level,
                "techniques_used": tc.techniques_used,
                "payload_preview": tc.payload[:200] + "..." if len(tc.payload) > 200 else tc.payload,
            }
            for tc in filtered
        ]
    }


@app.get("/api/corpus/{test_id}")
async def get_test_case(test_id: str):
    """Get single test case by ID"""
    corpus = _get_active_corpus()

    for tc in corpus:
        if tc.id == test_id:
            return {
                "id": tc.id,
                "name": tc.name,
                "category": tc.category.value,
                "severity": tc.severity.value,
                "description": tc.description,
                "payload": tc.payload,
                "expected_behavior": tc.expected_behavior,
                "success_indicators": tc.success_indicators,
                "complexity_level": tc.complexity_level,
                "techniques_used": tc.techniques_used,
                "chain_sequence": tc.chain_sequence,
                "target_models": tc.target_models,
                "research_source": tc.research_source,
                "technique_year": tc.technique_year,
            }

    raise HTTPException(status_code=404, detail="Test case not found")


@app.post("/api/corpus/generate")
async def generate_corpus(gen_req: GenerateRequest, _xhr=Depends(_require_xhr)):
    """
    Generate new corpus with optional target interpolation and category filtering.
    The generated corpus is stored in the module-level cache so that subsequent
    export and filter requests serve the same targeted corpus (finding M-11).
    Requires XHR header (M-7).
    """
    global _last_generated_corpus

    # Normalize empty string to None
    target = gen_req.target if gen_req.target else None
    generator = CorpusGenerator(target=target)
    output = generator.generate_all()

    # Filter by requested categories if provided
    if gen_req.categories:
        filtered_categories = {
            cat: cases for cat, cases in output.categories.items()
            if cat in gen_req.categories
        }
    else:
        filtered_categories = output.categories

    # Flatten and persist the target-interpolated corpus (finding M-11)
    all_cases = []
    for cases in filtered_categories.values():
        all_cases.extend(cases)
    _last_generated_corpus = all_cases

    # Also clear the default lru_cache so a follow-up /api/corpus (no target)
    # will regenerate fresh rather than serving a stale default (finding M-10)
    get_all_test_cases.cache_clear()

    total_count = len(all_cases)

    return {
        "success": True,
        "count": total_count,
        "target": target,
        "categories": {
            cat: len(cases) for cat, cases in filtered_categories.items()
        }
    }


@app.post("/api/corpus/regenerate")
async def regenerate_corpus():
    """
    Clear the corpus cache and force regeneration on next request (finding M-10).
    Also discards any previously generated target corpus.
    """
    global _last_generated_corpus
    get_all_test_cases.cache_clear()
    _last_generated_corpus = None
    return {"ok": True}


@app.get("/api/export/{format}")
async def export_corpus(format: str):
    """Export corpus as a real file download (finding L-10)"""
    corpus = _get_active_corpus()

    if format == "json":
        data = [
            {
                "id": tc.id,
                "name": tc.name,
                "category": tc.category.value,
                "severity": tc.severity.value,
                "payload": tc.payload,
            }
            for tc in corpus
        ]
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": "attachment; filename=corpus.json"},
        )

    elif format in ("md", "markdown"):
        md_content = "# 0xPrompt Test Corpus\n\n"
        for tc in corpus:
            md_content += (
                f"## {tc.name}\n"
                f"- **ID**: {tc.id}\n"
                f"- **Category**: {tc.category.value}\n"
                f"- **Severity**: {tc.severity.value}\n\n"
            )
        return Response(
            content=md_content,
            media_type="text/markdown",
            headers={"Content-Disposition": "attachment; filename=corpus.md"},
        )

    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Name", "Category", "Severity", "Description", "Payload"])
        for tc in corpus:
            # Guard against CSV formula injection (finding M-9)
            writer.writerow([
                _csv_safe(tc.id),
                _csv_safe(tc.name),
                _csv_safe(tc.category.value),
                _csv_safe(tc.severity.value),
                _csv_safe(tc.description[:100]),
                _csv_safe(tc.payload[:200]),
            ])
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=corpus.csv"},
        )

    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use: json, md, csv")


@app.get("/api/stats")
async def get_stats():
    """Get corpus statistics"""
    corpus = _get_active_corpus()

    return {
        "total_test_cases": len(corpus),
        "by_category": {
            cat.value: len([tc for tc in corpus if tc.category.value == cat.value])
            for cat in TaxonomyCategory
        },
        "by_severity": {
            sev: len([tc for tc in corpus if tc.severity.value == sev])
            for sev in ["critical", "high", "medium", "low", "info"]
        },
        "by_complexity": {
            level: len([tc for tc in corpus if tc.complexity_level == level])
            for level in range(1, 6)
        },
        "owasp_coverage": {
            owasp_id: {
                "name": info["name"],
                "count": len([tc for tc in corpus if tc.category.value in info["categories"]])
            }
            for owasp_id, info in OWASP_LLM_TOP_10.items()
        }
    }


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="0xPrompt corpus dashboard")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1). Use 0.0.0.0 only on trusted networks.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)",
    )
    args = parser.parse_args()

    print(
        f"Dashboard listening on http://{args.host}:{args.port} — "
        "corpus browser only. Bind to 0.0.0.0 only on trusted networks."
    )
    uvicorn.run(app, host=args.host, port=args.port)
