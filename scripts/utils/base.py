#!/usr/bin/env python3
"""
AI/ML Pentesting Framework - Base Utilities
Core infrastructure for all testing modules
"""

import json
import logging
import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, List, Dict, Callable
import requests


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackCategory(Enum):
    EVASION = "evasion"
    EXTRACTION = "extraction"
    INVERSION = "inversion"
    MEMBERSHIP_INFERENCE = "membership_inference"
    PROMPT_INJECTION = "prompt_injection"
    DATA_POISONING = "data_poisoning"
    DENIAL_OF_SERVICE = "dos"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class Finding:
    """Represents a security finding from testing"""
    id: str
    title: str
    category: AttackCategory
    severity: Severity
    description: str
    evidence: Dict[str, Any]
    remediation: str
    timestamp: datetime = field(default_factory=datetime.now)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    poc_code: Optional[str] = None

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['category'] = self.category.value
        result['severity'] = self.severity.value
        result['timestamp'] = self.timestamp.isoformat()
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class TestResult:
    """Result of a single test execution"""
    test_name: str
    success: bool
    attack_succeeded: bool
    metrics: Dict[str, Any]
    duration_seconds: float
    queries_used: int = 0
    findings: List[Finding] = field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None


class ModelInterface(ABC):
    """Abstract interface for interacting with target models"""

    @abstractmethod
    def predict(self, input_data: Any) -> Any:
        """Send input and get prediction"""
        pass

    @abstractmethod
    def get_probabilities(self, input_data: Any) -> Optional[List[float]]:
        """Get class probabilities if available"""
        pass

    @abstractmethod
    def get_logits(self, input_data: Any) -> Optional[List[float]]:
        """Get raw logits if available"""
        pass


class APIModelInterface(ModelInterface):
    """Interface for API-based model access"""

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        rate_limit: float = 1.0,  # requests per second
        timeout: int = 30
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.headers = headers or {}
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.query_count = 0
        self.last_query_time = 0

        if api_key:
            self.headers['Authorization'] = f'Bearer {api_key}'

        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.logger = logging.getLogger(self.__class__.__name__)

    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        if self.rate_limit > 0:
            elapsed = time.time() - self.last_query_time
            wait_time = (1.0 / self.rate_limit) - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
        self.last_query_time = time.time()

    def predict(self, input_data: Any) -> Any:
        self._rate_limit_wait()
        self.query_count += 1

        try:
            response = self.session.post(
                self.endpoint,
                json={"input": input_data},
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise

    def get_probabilities(self, input_data: Any) -> Optional[List[float]]:
        result = self.predict(input_data)
        return result.get('probabilities') or result.get('probs')

    def get_logits(self, input_data: Any) -> Optional[List[float]]:
        result = self.predict(input_data)
        return result.get('logits')


class LLMInterface(ModelInterface):
    """Interface for Large Language Model testing"""

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        model_name: str = "unknown",
        headers: Optional[Dict[str, str]] = None,
        rate_limit: float = 1.0,
        timeout: int = 60
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.model_name = model_name
        self.headers = headers or {}
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.query_count = 0
        self.last_query_time = 0
        self.conversation_history: List[Dict] = []

        if api_key:
            self.headers['Authorization'] = f'Bearer {api_key}'

        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.logger = logging.getLogger(self.__class__.__name__)

    def _rate_limit_wait(self):
        if self.rate_limit > 0:
            elapsed = time.time() - self.last_query_time
            wait_time = (1.0 / self.rate_limit) - elapsed
            if wait_time > 0:
                time.sleep(wait_time)
        self.last_query_time = time.time()

    def predict(self, input_data: Any) -> Any:
        """Send prompt and get response"""
        return self.chat(input_data if isinstance(input_data, str) else str(input_data))

    def chat(
        self,
        message: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        include_history: bool = True
    ) -> str:
        self._rate_limit_wait()
        self.query_count += 1

        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if include_history:
            messages.extend(self.conversation_history)

        messages.append({"role": "user", "content": message})

        try:
            response = self.session.post(
                self.endpoint,
                json={
                    "model": self.model_name,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                timeout=self.timeout
            )
            response.raise_for_status()

            result = response.json()
            assistant_message = result.get('choices', [{}])[0].get('message', {}).get('content', '')

            # Update conversation history
            self.conversation_history.append({"role": "user", "content": message})
            self.conversation_history.append({"role": "assistant", "content": assistant_message})

            return assistant_message

        except requests.RequestException as e:
            self.logger.error(f"LLM API request failed: {e}")
            raise

    def reset_conversation(self):
        """Clear conversation history"""
        self.conversation_history = []

    def get_probabilities(self, input_data: Any) -> Optional[List[float]]:
        return None  # LLMs typically don't expose probabilities

    def get_logits(self, input_data: Any) -> Optional[List[float]]:
        return None


class TestModule(ABC):
    """Base class for all testing modules"""

    def __init__(
        self,
        target: ModelInterface,
        output_dir: Path,
        config: Optional[Dict] = None
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}
        self.findings: List[Finding] = []
        self.results: List[TestResult] = []

        self.logger = logging.getLogger(self.__class__.__name__)
        self._setup_logging()

    def _setup_logging(self):
        log_file = self.output_dir / f"{self.__class__.__name__}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    @abstractmethod
    def run_tests(self) -> List[TestResult]:
        """Execute all tests in this module"""
        pass

    def add_finding(self, finding: Finding):
        """Record a security finding"""
        self.findings.append(finding)
        self.logger.warning(f"Finding: [{finding.severity.value.upper()}] {finding.title}")

    def generate_finding_id(self, prefix: str = "AIML") -> str:
        """Generate unique finding ID"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        return f"{prefix}-{timestamp}-{random_suffix.upper()}"

    def save_results(self, filename: Optional[str] = None):
        """Save test results to file"""
        if not filename:
            filename = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = self.output_dir / filename

        output = {
            "module": self.__class__.__name__,
            "timestamp": datetime.now().isoformat(),
            "config": self.config,
            "summary": {
                "total_tests": len(self.results),
                "successful_attacks": sum(1 for r in self.results if r.attack_succeeded),
                "total_findings": len(self.findings),
                "findings_by_severity": {
                    sev.value: sum(1 for f in self.findings if f.severity == sev)
                    for sev in Severity
                }
            },
            "findings": [f.to_dict() for f in self.findings],
            "results": [
                {
                    "test_name": r.test_name,
                    "success": r.success,
                    "attack_succeeded": r.attack_succeeded,
                    "metrics": r.metrics,
                    "duration_seconds": r.duration_seconds,
                    "queries_used": r.queries_used,
                    "error": r.error
                }
                for r in self.results
            ]
        }

        def json_serializer(obj):
            """Handle numpy and other non-JSON-serializable types"""
            import numpy as np
            if isinstance(obj, (np.bool_, np.integer)):
                return int(obj)
            if isinstance(obj, np.floating):
                return float(obj)
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            return str(obj)

        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2, default=json_serializer)

        self.logger.info(f"Results saved to {output_path}")
        return output_path


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure framework-wide logging"""
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
        ]
    )
    return logging.getLogger('aiml_pentest')


def load_config(config_path: Path) -> Dict:
    """Load configuration from JSON file"""
    with open(config_path) as f:
        return json.load(f)


def save_artifact(data: Any, path: Path, format: str = "json"):
    """Save testing artifact"""
    path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    elif format == "text":
        with open(path, 'w') as f:
            f.write(str(data))
    elif format == "binary":
        with open(path, 'wb') as f:
            f.write(data)
