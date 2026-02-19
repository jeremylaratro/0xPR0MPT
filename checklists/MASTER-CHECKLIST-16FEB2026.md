# AI/ML Penetration Testing Master Checklist
## Complete Testing Matrix with Checkpoints

**Engagement:** ____________________
**Tester:** ____________________
**Date Started:** ____________________
**Authorization Reference:** ____________________

---

## Phase 0: Pre-Engagement

### Authorization & Scope
- [ ] Written authorization obtained
- [ ] Scope document signed
- [ ] Testing boundaries defined
- [ ] Emergency contacts established
- [ ] Data handling agreement in place
- [ ] NDA executed (if required)

### Environment Setup
- [ ] Testing environment prepared
- [ ] Required tools installed
- [ ] API credentials received
- [ ] Network access verified
- [ ] Logging configured
- [ ] Backup/rollback procedures documented

**CHECKPOINT 0:** Pre-engagement complete
- Date: ____
- Sign-off: ____

---

## Phase 1: Reconnaissance

### 1.1 Passive Intelligence Gathering
- [ ] OSINT on ML infrastructure
- [ ] Public model cards reviewed
- [ ] GitHub/GitLab repositories searched
- [ ] Documentation analyzed
- [ ] Job postings reviewed for tech stack
- [ ] Conference talks/papers reviewed
- [ ] Social media intelligence
- [ ] HuggingFace/Model Zoo searched
- [ ] Docker Hub images identified

### 1.2 Technology Stack Identification
- [ ] ML Framework identified: ____________________
- [ ] Serving infrastructure: ____________________
- [ ] API Gateway: ____________________
- [ ] Cloud provider: ____________________
- [ ] Version information: ____________________

### 1.3 API Enumeration
- [ ] Endpoints discovered: ____________________
- [ ] Authentication method: ____________________
- [ ] Rate limits identified: ____________________
- [ ] Input formats documented
- [ ] Output formats documented
- [ ] Error response patterns captured

### 1.4 Model Fingerprinting
- [ ] Model type determined (classification/regression/generative)
- [ ] Input dimensions identified
- [ ] Output dimensions identified
- [ ] Class count (if applicable)
- [ ] Confidence score format
- [ ] Preprocessing requirements

**CHECKPOINT 1:** Reconnaissance complete
- Date: ____
- Findings documented: ____
- Attack surface mapped: [ ]

---

## Phase 2: Model Security Testing

### 2.1 Model Extraction Assessment
- [ ] Query-based extraction feasibility assessed
- [ ] Surrogate model architecture selected
- [ ] Training data generation strategy defined
- [ ] Extraction attack executed
- [ ] Extraction fidelity measured: ____%
- [ ] Query cost documented: ____
- [ ] Time required: ____

**Extraction Results:**
| Metric | Value |
|--------|-------|
| Agreement Rate | |
| Queries Used | |
| Time to Extract | |
| Fidelity Score | |

### 2.2 Model Inversion Testing
- [ ] Gradient availability assessed
- [ ] Confidence scores exploited
- [ ] Feature reconstruction attempted
- [ ] Training data reconstruction attempted
- [ ] Reconstruction quality: ____

### 2.3 Membership Inference
- [ ] Shadow models trained
- [ ] Attack model trained
- [ ] Attack accuracy: ____%
- [ ] TPR at low FPR documented
- [ ] Privacy risk level: ____

**CHECKPOINT 2:** Model security testing complete
- Date: ____
- Critical findings: ____
- Risk level: ____

---

## Phase 3: Adversarial Robustness Testing

### 3.1 White-Box Attacks (if applicable)
- [ ] FGSM tested
  - Success rate: ____%
  - ε value: ____
- [ ] PGD tested
  - Success rate: ____%
  - Iterations: ____
- [ ] C&W tested
  - Success rate: ____%
  - Confidence: ____
- [ ] DeepFool tested
  - Success rate: ____%
  - Perturbation: ____
- [ ] AutoAttack tested
  - Robust accuracy: ____%

### 3.2 Black-Box Attacks
- [ ] Transfer attack (from surrogate)
  - Success rate: ____%
- [ ] Score-based attack
  - Success rate: ____%
  - Queries: ____
- [ ] Decision-based attack
  - Success rate: ____%
  - Queries: ____
- [ ] Query-efficient attack
  - Success rate: ____%

### 3.3 Physical Attacks (if applicable)
- [ ] Adversarial patch generation
- [ ] Printability constraints tested
- [ ] Real-world effectiveness: ____%

**CHECKPOINT 3:** Adversarial testing complete
- Date: ____
- Most effective attack: ____________________
- Robustness rating: ____/10

---

## Phase 4: Prompt Injection Testing (LLMs)

### 4.1 System Prompt Extraction
- [ ] Direct extraction attempted
- [ ] Indirect extraction attempted
- [ ] System prompt obtained: [ ] Yes [ ] No [ ] Partial

### 4.2 Direct Injection
- [ ] Basic instruction override
- [ ] Role-playing attacks
- [ ] Language switching
- [ ] Encoding attacks (base64, ROT13, etc.)
- [ ] Token manipulation
- [ ] Delimiter confusion
- [ ] Multi-turn attacks
- [ ] Context overflow

**Successful Techniques:**
| Technique | Payload Reference | Notes |
|-----------|-------------------|-------|
| | | |
| | | |

### 4.3 Jailbreak Testing
- [ ] DAN-style prompts
- [ ] Hypothetical framing
- [ ] Gradual escalation
- [ ] Encoded payloads
- [ ] Multi-language confusion
- [ ] Token smuggling

**Successful Jailbreaks:**
| Category | Success Rate | Reliability |
|----------|--------------|-------------|
| | | |

### 4.4 Indirect Injection
- [ ] RAG poisoning tested
- [ ] Tool output injection
- [ ] External data injection
- [ ] Multimodal injection (images)

### 4.5 Defense Analysis
- [ ] Input filtering identified
- [ ] Output filtering identified
- [ ] Filter bypass techniques tested
- [ ] Defense effectiveness rating: ____/10

**CHECKPOINT 4:** Prompt injection testing complete
- Date: ____
- Jailbreak reliability: ____%
- Defense bypass success: ____%

---

## Phase 5: Data Security Testing

### 5.1 Training Data Exposure
- [ ] Memorization probing
- [ ] Verbatim text extraction (LLMs)
- [ ] PII extraction attempts
- [ ] Sensitive pattern discovery

**Extracted Data:**
| Type | Quantity | Severity |
|------|----------|----------|
| PII | | |
| Credentials | | |
| Proprietary | | |

### 5.2 Data Poisoning Feasibility
- [ ] Data pipeline access assessed
- [ ] Injection points identified
- [ ] Backdoor injection tested (if authorized)
- [ ] Poisoning detection mechanisms assessed

### 5.3 Differential Privacy Assessment
- [ ] DP implementation verified
- [ ] Epsilon budget documented: ____
- [ ] Privacy guarantees validated

**CHECKPOINT 5:** Data security testing complete
- Date: ____
- Data exposure risk: ____
- Poisoning feasibility: ____

---

## Phase 6: Infrastructure Security

### 6.1 API Security
- [ ] Authentication bypass attempts
- [ ] Authorization testing
- [ ] Rate limiting effectiveness
- [ ] Input validation testing
- [ ] Injection vulnerabilities (SQL, NoSQL, etc.)
- [ ] Error message information disclosure
- [ ] API versioning security

### 6.2 Model Serving Security
- [ ] Model file access tested
- [ ] Weight extraction attempted
- [ ] Configuration exposure
- [ ] Debugging endpoints
- [ ] Admin interfaces

### 6.3 Container/Cloud Security
- [ ] Container escape attempts
- [ ] Metadata service access
- [ ] IAM misconfigurations
- [ ] Storage bucket permissions
- [ ] Network segmentation

**CHECKPOINT 6:** Infrastructure testing complete
- Date: ____
- Vulnerabilities found: ____
- Severity distribution: ____

---

## Phase 7: Supply Chain Analysis

### 7.1 Dependency Assessment
- [ ] ML framework CVE scan
- [ ] Python dependency scan
- [ ] Container base image scan
- [ ] Third-party model audit

### 7.2 Model Provenance
- [ ] Pre-trained model source verified
- [ ] Model signatures validated
- [ ] Backdoor scan performed
- [ ] Training data provenance checked

**Vulnerabilities Found:**
| Component | CVE/Issue | Severity | Exploitable |
|-----------|-----------|----------|-------------|
| | | | |

**CHECKPOINT 7:** Supply chain analysis complete
- Date: ____
- Supply chain risk level: ____

---

## Phase 8: Privacy Attack Assessment

### 8.1 Advanced Privacy Attacks
- [ ] Attribute inference tested
- [ ] Property inference tested
- [ ] Distributional inference tested

### 8.2 Federated Learning (if applicable)
- [ ] Gradient leakage tested
- [ ] Model poisoning tested
- [ ] Free-rider detection tested

**CHECKPOINT 8:** Privacy assessment complete
- Date: ____
- Privacy risk rating: ____

---

## Phase 9: Denial of Service

### 9.1 Resource Exhaustion
- [ ] Sponge examples tested
- [ ] Computational DoS tested
- [ ] Memory exhaustion tested
- [ ] Concurrent request limits

### 9.2 Model Degradation
- [ ] Performance degradation attacks
- [ ] Availability impact assessment

**CHECKPOINT 9:** DoS testing complete
- Date: ____

---

## Phase 10: Reporting

### 10.1 Documentation
- [ ] All findings documented
- [ ] Evidence collected
- [ ] PoCs created and tested
- [ ] Screenshots captured
- [ ] Logs preserved

### 10.2 Report Generation
- [ ] Executive summary written
- [ ] Technical findings documented
- [ ] Risk ratings assigned
- [ ] Remediation recommendations provided
- [ ] Report reviewed for accuracy

### 10.3 Cleanup
- [ ] Test artifacts removed
- [ ] Credentials rotated (if applicable)
- [ ] Access revoked
- [ ] Logs secured

**FINAL CHECKPOINT:** Engagement complete
- Date: ____
- Total findings: ____
- Critical: ____
- High: ____
- Medium: ____
- Low: ____
- Info: ____
- Report delivered: ____
- Debrief completed: ____

---

## Finding Summary

| ID | Title | Category | Severity | Status |
|----|-------|----------|----------|--------|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

---

## Notes & Observations

```
[Space for tester notes]








```

---

## Sign-Off

**Tester Signature:** ____________________
**Date Completed:** ____________________
**Technical Review By:** ____________________
**Date:** ____________________
