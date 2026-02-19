#!/usr/bin/env python3
"""
0xPrompt - LLM Exploitation Framework by d0sf3t
Web console for AI/ML red teaming with OWASP LLM Top 10 filters
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
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
    description="LLM Exploitation Framework by d0sf3t",
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

# Active WebSocket connections
active_connections: List[WebSocket] = []


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
    target: Optional[str] = None  # Target for payload interpolation (e.g., "User ID 02")


class TestExecuteRequest(BaseModel):
    test_ids: List[str]
    target_endpoint: str
    api_key: Optional[str] = None


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
    """Test execution page"""
    return templates.TemplateResponse("executor.html", {
        "request": request,
    })


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# =============================================================================
# Helper Functions
# =============================================================================

def get_all_test_cases():
    """Get flattened list of all test cases from generator"""
    generator = CorpusGenerator()
    output = generator.generate_all()
    all_cases = []
    for cases in output.categories.values():
        all_cases.extend(cases)
    return all_cases


# =============================================================================
# Routes - API
# =============================================================================

@app.get("/api/corpus")
async def list_corpus():
    """List all test cases"""
    corpus = get_all_test_cases()

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
    owasp: str = Form(default=""),
    category: str = Form(default=""),
    severity: str = Form(default=""),
    model: str = Form(default=""),
    complexity: str = Form(default=""),
    search: str = Form(default=""),
):
    """Filter test cases (accepts form data from HTMX)"""
    corpus = get_all_test_cases()
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
    corpus = get_all_test_cases()

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
async def generate_corpus(gen_req: GenerateRequest):
    """Generate new corpus with optional target interpolation and category filtering"""
    # Normalize empty string to None
    target = gen_req.target if gen_req.target else None
    # Pass target to generator for payload interpolation
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

    # Count test cases from filtered output
    total_count = sum(len(cases) for cases in filtered_categories.values())

    return {
        "success": True,
        "count": total_count,
        "target": target,  # Return normalized target (None if empty)
        "categories": {
            cat: len(cases) for cat, cases in filtered_categories.items()
        }
    }


@app.get("/api/export/{format}")
async def export_corpus(format: str):
    """Export corpus in specified format"""
    corpus = get_all_test_cases()

    if format == "json":
        import json as json_lib
        data = [{"id": tc.id, "name": tc.name, "category": tc.category.value,
                 "severity": tc.severity.value, "payload": tc.payload} for tc in corpus]
        return JSONResponse(content=data)
    elif format == "md" or format == "markdown":
        md_content = "# 0xPrompt Test Corpus\n\n"
        for tc in corpus:
            md_content += f"## {tc.name}\n- **ID**: {tc.id}\n- **Category**: {tc.category.value}\n- **Severity**: {tc.severity.value}\n\n"
        return JSONResponse(content={"markdown": md_content})
    elif format == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Name", "Category", "Severity", "Description", "Payload"])
        for tc in corpus:
            writer.writerow([tc.id, tc.name, tc.category.value, tc.severity.value, tc.description[:100], tc.payload[:200]])
        return JSONResponse(content={"csv": output.getvalue()})
    else:
        raise HTTPException(status_code=400, detail="Invalid format. Use: json, md, csv")


@app.get("/api/stats")
async def get_stats():
    """Get corpus statistics"""
    corpus = get_all_test_cases()

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
# WebSocket - Real-time Test Results
# =============================================================================

@app.websocket("/ws/results/{job_id}")
async def websocket_results(websocket: WebSocket, job_id: str):
    """WebSocket for real-time test results"""
    await websocket.accept()
    active_connections.append(websocket)

    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "connected",
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat()
        })

        # Keep connection alive and handle messages
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
            elif message.get("type") == "start_test":
                # Simulate test execution
                await simulate_test_execution(websocket, message.get("test_ids", []))

    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def simulate_test_execution(websocket: WebSocket, test_ids: List[str]):
    """Simulate test execution and send results"""
    corpus = get_all_test_cases()

    tests_to_run = [tc for tc in corpus if tc.id in test_ids] if test_ids else corpus[:10]

    await websocket.send_json({
        "type": "execution_started",
        "total_tests": len(tests_to_run)
    })

    for i, tc in enumerate(tests_to_run):
        # Simulate execution delay
        await asyncio.sleep(0.5)

        # Send result
        await websocket.send_json({
            "type": "test_result",
            "test_name": tc.name,
            "test_id": tc.id,
            "success": True,
            "attack_succeeded": i % 3 == 0,  # Simulate 1/3 success rate
            "duration": 0.5,
            "progress": (i + 1) / len(tests_to_run)
        })

    await websocket.send_json({
        "type": "execution_complete",
        "total_tests": len(tests_to_run),
        "timestamp": datetime.utcnow().isoformat()
    })


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
