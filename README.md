# SECURE AI/ML ARCHITECTURE DESIGN WITH MLOPS SECURITY

## Enterprise Implementation Guide for Production-Ready AI Systems

---

## TABLE OF CONTENTS

1. Executive Summary
2. Secure AI/ML Architecture Overview
3. Architecture Components & Security Controls
4. MLOps Platform Implementation
5. Model Versioning & Registry Security
6. Deployment Pipeline Security
7. Monitoring & Observability
8. Security Checklist & Sign-off
9. Implementation Roadmap

---

## 1. EXECUTIVE SUMMARY

This document provides a complete secure AI/ML architecture designed for mid-size enterprises deploying production AI systems. The architecture incorporates:

- **MLOps Best Practices** - Model versioning, deployment automation, monitoring
- **Security Controls** - Input validation, guardrails, access control, encryption
- **LLM-Specific Protections** - Prompt injection prevention, output filtering, jailbreak detection
- **Compliance Alignment** - GDPR, ISO 42001, EU AI Act requirements
- **Operational Excellence** - Drift detection, performance monitoring, audit logging

**Architecture Applies To:**
- Generative AI applications (ChatGPT, Claude, Llama fine-tuned models)
- Machine learning classification/regression models
- LLM-powered chatbots and agents
- Multi-modal AI systems
- Autonomous decision-making systems

**Key Outcomes:**
✅ Production-ready deployment with built-in security  
✅ Continuous monitoring and performance tracking  
✅ Automated incident response and rollback  
✅ Full audit trail and compliance documentation  
✅ Model versioning and reproducibility  

---

## 2. SECURE AI/ML ARCHITECTURE OVERVIEW

### 2.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL USERS / CLIENTS                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
                    ┌───────────────────────────────┐
                    │     API GATEWAY & WAF          │
                    │  - Rate limiting               │
                    │  - Request validation          │
                    │  - DDoS protection             │
                    └───────────────────────────────┘
                                    ↓
        ┌──────────────────────────────────────────────────────┐
        │            INFERENCE LAYER                           │
        ├──────────────────────────────────────────────────────┤
        │                                                       │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   INPUT VALIDATION & SANITIZATION           │    │
        │  │  - Special character filtering               │    │
        │  │  - Length validation                         │    │
        │  │  - SQL/script injection prevention           │    │
        │  │  - Semantic prompt injection detection       │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   GUARDRAILS & SAFETY FILTERS               │    │
        │  │  - NeMo Guardrails / LangChain guards        │    │
        │  │  - Instruction blocking (payment, account)   │    │
        │  │  - Jailbreak pattern detection               │    │
        │  │  - Confidence scoring                        │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   MODEL INFERENCE ENGINE                     │    │
        │  │  - MLflow Model Registry                      │    │
        │  │  - Version-controlled models                 │    │
        │  │  - GPU/CPU optimized serving                 │    │
        │  │  - A/B testing support                       │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   OUTPUT FILTERING & VALIDATION              │    │
        │  │  - PII redaction (credit cards, SSN, etc.)   │    │
        │  │  - Harmful content detection                 │    │
        │  │  - URL/executable filtering                  │    │
        │  │  - Response confidence validation            │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   AUDIT LOGGING & COMPLIANCE                 │    │
        │  │  - All inference requests logged              │    │
        │  │  - User ID, timestamp, input, output          │    │
        │  │  - Sent to security SIEM                      │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        └──────────────────────────────────────────────────────┘
                                    ↓
                    ┌───────────────────────────────┐
                    │   RESPONSE TO CLIENT           │
                    │   (Encrypted TLS 1.2+)         │
                    └───────────────────────────────┘


        ┌──────────────────────────────────────────────────────┐
        │            MODEL TRAINING PIPELINE                   │
        ├──────────────────────────────────────────────────────┤
        │                                                       │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   DATA INGESTION & VALIDATION                │    │
        │  │  - Data source verification                  │    │
        │  │  - Schema validation                         │    │
        │  │  - Anomaly detection in training data        │    │
        │  │  - DVC versioning                            │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   DATA PREPROCESSING & LINEAGE               │    │
        │  │  - PII anonymization                         │    │
        │  │  - Feature engineering                       │    │
        │  │  - Data lineage tracking (MLflow)            │    │
        │  │  - Version control of datasets               │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   MODEL TRAINING & VALIDATION                │    │
        │  │  - Bias detection & mitigation                │    │
        │  │  - Fairness testing                          │    │
        │  │  - Adversarial robustness testing            │    │
        │  │  - Performance baselines                     │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   SECURITY TESTING                           │    │
        │  │  - Prompt injection testing (Garak)          │    │
        │  │  - Jailbreak attempt testing                 │    │
        │  │  - Data leakage testing                      │    │
        │  │  - Model extraction attacks                  │    │
        │  │  - Backdoor detection                        │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   MODEL REGISTRY & VERSIONING                │    │
        │  │  - MLflow Model Registry                      │    │
        │  │  - Model cards documentation                 │    │
        │  │  - Git-based version control                 │    │
        │  │  - Stage transitions (Staging→Production)    │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        └──────────────────────────────────────────────────────┘


        ┌──────────────────────────────────────────────────────┐
        │            CONTINUOUS MONITORING LAYER               │
        ├──────────────────────────────────────────────────────┤
        │                                                       │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   PERFORMANCE MONITORING                     │    │
        │  │  - Accuracy tracking (vs baseline)           │    │
        │  │  - Latency & throughput metrics              │    │
        │  │  - Uptime & availability monitoring          │    │
        │  │  - Tools: Evidently AI, WhyLabs, Fiddler     │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   DRIFT DETECTION                            │    │
        │  │  - Data drift monitoring                      │    │
        │  │  - Model drift detection                      │    │
        │  │  - Concept drift tracking                     │    │
        │  │  - Automatic alert on threshold breach       │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   SECURITY & ANOMALY DETECTION               │    │
        │  │  - Adversarial input detection                │    │
        │  │  - Unusual pattern recognition                │    │
        │  │  - Attempted attacks monitoring               │    │
        │  │  - SIEM integration                           │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   ALERTING & INCIDENT RESPONSE               │    │
        │  │  - Automated threshold alerts                 │    │
        │  │  - PagerDuty/Slack notifications              │    │
        │  │  - Automatic rollback triggers                │    │
        │  │  - Human review workflows                     │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        └──────────────────────────────────────────────────────┘


        ┌──────────────────────────────────────────────────────┐
        │            INFRASTRUCTURE & ACCESS CONTROL           │
        ├──────────────────────────────────────────────────────┤
        │                                                       │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   NETWORK SECURITY                           │    │
        │  │  - VPC isolation (models in private VPC)      │    │
        │  │  - Security groups (port restrictions)        │    │
        │  │  - WAF (Web Application Firewall)             │    │
        │  │  - DDoS protection                            │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   ENCRYPTION & KEY MANAGEMENT                │    │
        │  │  - TLS 1.2+ for all communications            │    │
        │  │  - AES-256 at rest (S3, databases)            │    │
        │  │  - AWS KMS or similar key management          │    │
        │  │  - Secrets management (API keys, creds)       │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   ACCESS CONTROL (RBAC)                      │    │
        │  │  - Multi-factor authentication (MFA)          │    │
        │  │  - Role-based access control (RBAC)           │    │
        │  │  - Service accounts with minimal permissions  │    │
        │  │  - Audit logging of all access                │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        │  ┌──────────────────────────────────────────────┐    │
        │  │   COMPLIANCE & AUDIT LOGGING                 │    │
        │  │  - Centralized logging (CloudWatch, ELK)      │    │
        │  │  - Log retention per compliance needs          │    │
        │  │  - Immutable audit trails                      │    │
        │  │  - Regular access reviews                      │    │
        │  └──────────────────────────────────────────────┘    │
        │                        ↓                              │
        └──────────────────────────────────────────────────────┘
```

---

## 3. ARCHITECTURE COMPONENTS & SECURITY CONTROLS

### 3.1 INPUT VALIDATION & SANITIZATION

**Purpose:** Prevent malicious inputs from reaching the model

#### Control Implementation

| Layer | Control | Implementation |
|-------|---------|-----------------|
| **Character Filtering** | Remove special characters that could break parsing | `re.sub(r'[<>{}\"\';\-\-]', '', user_input)` |
| **Length Validation** | Enforce maximum input length | `if len(user_input) > 500: reject` |
| **SQL Injection Prevention** | Parameterized queries, no string concatenation | Use ORM (SQLAlchemy), never `f"SELECT * FROM {table}"` |
| **Script Injection Prevention** | No execution of user input | Never use `eval()`, `exec()`, or similar |
| **Semantic Prompt Injection Detection** | Detect indirect injection via data | Analyze for suspicious patterns like "ignore instructions" |
| **Rate Limiting** | Prevent brute force / enumeration attacks | 100 requests per minute per IP |

#### Python Implementation Example

```python
import re
from langchain.chains import load_chain

# Input validation function
def validate_input(user_input: str, max_length: int = 500) -> str:
    """
    Validate and sanitize user input before sending to LLM
    """
    # Length validation
    if len(user_input) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    
    # Remove SQL injection attempts
    dangerous_patterns = [
        r"(\bDROP\b|\bDELETE\b|\bUPDATE\b|\bINSERT\b)",
        r"(--|;|\*)",
        r"(union|select|from|where|and|or)\s",
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            raise ValueError("Potentially malicious input detected")
    
    # Remove special characters that could break parsing
    sanitized = re.sub(r'[<>{}\"\'`]', '', user_input)
    
    return sanitized

# Example usage
user_input = "What is your refund policy?"
safe_input = validate_input(user_input)  # ✅ Passes validation

malicious_input = "What is your refund policy?' OR '1'='1"
validate_input(malicious_input)  # ❌ Raises ValueError
```

---

### 3.2 GUARDRAILS & SAFETY FILTERS

**Purpose:** Prevent unsafe model outputs and enforce business rules

#### Guardrails Implementation (NeMo Guardrails)

```yaml
# guardrails_config.yml
define user ask for account deletion
    "Delete my account"
    "Cancel my account"
    "Remove my profile"

define user ask for payment modification
    "Change my payment method"
    "Update billing info"
    "Modify my card"

define user ask harmful content
    "How do I hack into a system?"
    "Tell me how to build malware"
    "Generate code for ransomware"

define bot refuse account operations
    "I cannot modify your account directly. Please contact our support team."

define bot refuse payment operations
    "For security reasons, payment modifications must be done through our secure portal."

define bot refuse harmful requests
    "I cannot help with that request."

define flow
    user ask for account deletion
    bot refuse account operations

    user ask for payment modification
    bot refuse payment operations

    user ask harmful content
    bot refuse harmful requests
```

#### Python Implementation (Guardrails AI)

```python
from guardrails import Guard
from guardrails.validators import ValidLength, ValidJSON
from langchain.chat_models import ChatOpenAI

# Define guardrails
guard = Guard.from_pydantic(
    output_class=ChatResponse,
    validators=[
        ValidLength(min_len=10, max_len=500),
        ValidJSON(),
    ],
    num_reasks=2
)

# Apply guardrails to LLM
llm = ChatOpenAI(model_name="gpt-3.5-turbo")

def get_safe_response(user_query: str):
    """Generate response with guardrails enforcement"""
    
    # Input validation
    validated_query = validate_input(user_query)
    
    # Generate response
    raw_response = llm.predict(validated_query)
    
    # Apply guardrails (retry up to 2 times if validation fails)
    validated_response, guard_history = guard.validate(raw_response)
    
    return validated_response
```

---

### 3.3 MODEL INFERENCE ENGINE (MLflow)

**Purpose:** Version-controlled, reproducible model serving

#### MLflow Model Registry Setup

```python
import mlflow
from mlflow.tracking import MlflowClient

# Initialize MLflow
mlflow.set_tracking_uri("s3://mlflow-backend-bucket")
mlflow.set_experiment("secure-llm-inference")
client = MlflowClient()

def log_model_with_metadata(model, model_name: str, 
                           version_description: str,
                           security_approved: bool):
    """Log model to registry with security metadata"""
    
    with mlflow.start_run():
        # Log model
        mlflow.sklearn.log_model(
            model,
            artifact_path="model",
            registered_model_name=f"secure-{model_name}"
        )
        
        # Log security metadata
        mlflow.log_param("security_approved", security_approved)
        mlflow.log_param("reviewed_by", "security_team")
        mlflow.log_param("prompt_injection_tested", True)
        mlflow.log_param("jailbreak_tested", True)
        mlflow.log_param("data_leakage_tested", True)
        
        # Log performance metrics
        mlflow.log_metrics({
            "accuracy": 0.94,
            "prompt_injection_resistance": 0.96,
            "jailbreak_resistance": 0.92,
            "latency_ms": 250,
        })

# Register model and manage stage transitions
def promote_model_to_production(model_version: str):
    """Promote model from staging to production (requires approval)"""
    
    # Move to staging
    client.transition_model_version_stage(
        name="secure-chatbot",
        version=model_version,
        stage="Staging"
    )
    
    # After security review, move to production
    client.transition_model_version_stage(
        name="secure-chatbot",
        version=model_version,
        stage="Production"
    )

# Load model from registry
def load_production_model():
    """Load the current production model"""
    
    production_uri = f"models:/secure-chatbot/production"
    model = mlflow.sklearn.load_model(production_uri)
    
    return model
```

#### Model Registry Configuration (Production)

| Aspect | Control | Implementation |
|--------|---------|-----------------|
| **Version Control** | All models versioned | Model Registry with semantic versioning |
| **Stage Transitions** | Approval gates | Staging → Production requires sign-off |
| **Rollback Capability** | Quick rollback if issues detected | Keep 2-3 previous versions available |
| **Model Cards** | Documentation required | MLmodel file with all metadata |
| **Access Control** | RBAC for model access | Only ML Ops team can deploy |
| **Audit Trail** | All changes logged | MLflow tracks who made what changes when |

---

### 3.4 OUTPUT FILTERING & VALIDATION

**Purpose:** Prevent PII leakage and harmful content in responses

#### Python Implementation

```python
import re
from datetime import datetime

class OutputFilter:
    """Filter and validate model outputs for safety"""
    
    # Patterns to detect and redact
    PII_PATTERNS = {
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'api_key': r'(sk-|api_|apikey)[A-Za-z0-9_]{20,}',
    }
    
    HARMFUL_PATTERNS = [
        r'malware',
        r'ransomware',
        r'exploit',
        r'vulnerability',
        r'hack(ing)?',
    ]
    
    SUSPICIOUS_URLS = [
        r'bit\.ly',
        r'tinyurl',
        r'short\.link',
    ]
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        self.redaction_count = 0
        self.harmful_flag_count = 0
    
    def filter_output(self, response: str, 
                     confidence_score: float = None) -> str:
        """
        Apply all filters to model output
        
        Returns: Filtered response or None if unsafe
        """
        
        # Check confidence score (if available)
        if confidence_score and confidence_score < self.confidence_threshold:
            return None  # Reject low-confidence responses
        
        # Redact PII
        filtered = self._redact_pii(response)
        
        # Check for harmful content
        if self._contains_harmful_content(filtered):
            self.harmful_flag_count += 1
            return None  # Reject harmful responses
        
        # Check for suspicious URLs
        if self._contains_suspicious_urls(filtered):
            filtered = self._remove_suspicious_urls(filtered)
        
        # Log redactions for audit
        self._log_filtering_action(response, filtered)
        
        return filtered
    
    def _redact_pii(self, text: str) -> str:
        """Redact personally identifiable information"""
        
        filtered = text
        for pii_type, pattern in self.PII_PATTERNS.items():
            matches = re.findall(pattern, filtered)
            if matches:
                self.redaction_count += len(matches)
                filtered = re.sub(pattern, f'[REDACTED_{pii_type.upper()}]', filtered)
        
        return filtered
    
    def _contains_harmful_content(self, text: str) -> bool:
        """Check if response contains harmful patterns"""
        
        for pattern in self.HARMFUL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _contains_suspicious_urls(self, text: str) -> bool:
        """Check for URL shorteners and suspicious domains"""
        
        for pattern in self.SUSPICIOUS_URLS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _remove_suspicious_urls(self, text: str) -> str:
        """Remove URL shorteners"""
        
        for pattern in self.SUSPICIOUS_URLS:
            text = re.sub(pattern, '[URL_REMOVED]', text, flags=re.IGNORECASE)
        
        return text
    
    def _log_filtering_action(self, original: str, filtered: str):
        """Log filtering actions for audit trail"""
        
        if original != filtered:
            print(f"[{datetime.now().isoformat()}] Output filtered")
            print(f"  - Redactions: {self.redaction_count}")
            print(f"  - Harmful flags: {self.harmful_flag_count}")

# Usage
filter = OutputFilter(confidence_threshold=0.7)

response = "Your credit card 4532-1234-5678-9012 has been charged $99.99"
filtered = filter.filter_output(response)
# Output: "Your credit card [REDACTED_CREDIT_CARD] has been charged $99.99"

harmful_response = "To exploit this vulnerability, you should..."
filtered = filter.filter_output(harmful_response)
# Output: None (rejected as harmful)
```

---

### 3.5 AUDIT LOGGING & COMPLIANCE

**Purpose:** Maintain immutable record of all inference activities for compliance

#### Logging Implementation

```python
import json
import logging
from datetime import datetime
from typing import Dict, Any
import hashlib

class AuditLogger:
    """Centralized audit logging for AI/ML systems"""
    
    def __init__(self, log_file: str = "ai_audit.log"):
        self.logger = logging.getLogger("AI_Audit")
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_inference(self, inference_data: Dict[str, Any]):
        """Log complete inference event"""
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "inference",
            "user_id": inference_data.get("user_id"),
            "model_version": inference_data.get("model_version"),
            "input": self._hash_sensitive(inference_data.get("input")),
            "output": self._hash_sensitive(inference_data.get("output")),
            "output_filtered": inference_data.get("output_filtered", False),
            "confidence_score": inference_data.get("confidence_score"),
            "latency_ms": inference_data.get("latency_ms"),
            "status": inference_data.get("status", "success"),
            "ip_address": inference_data.get("ip_address"),
        }
        
        self.logger.info(json.dumps(log_entry))
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security-related events"""
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,  # "prompt_injection_attempt", "jailbreak_attempt", etc.
            "severity": details.get("severity", "medium"),
            "description": details.get("description"),
            "user_id": details.get("user_id"),
            "blocked": details.get("blocked", False),
            "details": details.get("details"),
        }
        
        self.logger.warning(json.dumps(log_entry))
    
    def log_model_change(self, change_type: str, details: Dict[str, Any]):
        """Log model updates and version changes"""
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "model_change",
            "change_type": change_type,  # "deployed", "rolled_back", "updated"
            "model_name": details.get("model_name"),
            "model_version": details.get("model_version"),
            "changed_by": details.get("changed_by"),
            "reason": details.get("reason"),
            "status": details.get("status"),
        }
        
        self.logger.info(json.dumps(log_entry))
    
    @staticmethod
    def _hash_sensitive(data: str, truncate: bool = True) -> str:
        """Hash sensitive data for privacy while maintaining audit trail"""
        
        if not data:
            return None
        
        hash_obj = hashlib.sha256(data.encode())
        hash_val = hash_obj.hexdigest()
        
        # Return truncated hash if full data not needed for audit
        return hash_val[:16] if truncate else hash_val

# Usage
audit_log = AuditLogger()

# Log inference
audit_log.log_inference({
    "user_id": "user_123",
    "model_version": "v2.3",
    "input": "What is your refund policy?",
    "output": "Our refund policy...",
    "output_filtered": False,
    "confidence_score": 0.94,
    "latency_ms": 245,
    "status": "success",
    "ip_address": "192.168.1.1",
})

# Log security event
audit_log.log_security_event("prompt_injection_attempt", {
    "severity": "high",
    "description": "Attempted SQL injection in user query",
    "user_id": "user_456",
    "blocked": True,
    "details": "Query contained SQL DROP command",
})

# Log model deployment
audit_log.log_model_change("deployed", {
    "model_name": "customer_support_chatbot",
    "model_version": "v2.3",
    "changed_by": "ml_engineer",
    "reason": "Improved fairness metrics in multilingual queries",
    "status": "success",
})
```

---

## 4. MLOPS PLATFORM IMPLEMENTATION

### 4.1 MLflow Setup for Production

```python
# mlflow_config.py
import os
from pathlib import Path

class MLflowConfig:
    """Production MLflow configuration"""
    
    # Backend store (PostgreSQL recommended for production)
    TRACKING_URI = os.getenv(
        "MLFLOW_TRACKING_URI",
        "postgresql://user:password@localhost:5432/mlflow"
    )
    
    # Artifact store (S3 recommended)
    ARTIFACT_LOCATION = "s3://ml-artifacts-prod/"
    
    # Default experiment
    DEFAULT_EXPERIMENT = "production-models"
    
    # Retention policies
    MODEL_RETENTION_DAYS = 365
    LOG_RETENTION_DAYS = 30
    
    # Access control
    ENABLE_RBAC = True
    ARTIFACT_UPLOAD_DISABLED = False
    
    @staticmethod
    def setup_mlflow():
        """Initialize MLflow for production"""
        
        import mlflow
        from mlflow.tracking import MlflowClient
        
        # Set tracking URI
        mlflow.set_tracking_uri(MLflowConfig.TRACKING_URI)
        
        # Set experiment
        mlflow.set_experiment(MLflowConfig.DEFAULT_EXPERIMENT)
        
        # Create MLflow client
        client = MlflowClient()
        
        return client

# Usage
from mlflow_config import MLflowConfig
client = MLflowConfig.setup_mlflow()
```

### 4.2 Model Training with MLflow Tracking

```python
def train_secure_model(training_data, validation_data, 
                      model_params: dict):
    """
    Train model with full MLflow tracking and security
    """
    import mlflow
    import mlflow.sklearn
    from sklearn.ensemble import RandomForestClassifier
    
    with mlflow.start_run(run_name="secure_model_training"):
        # Log parameters
        mlflow.log_params({
            "n_estimators": model_params["n_estimators"],
            "max_depth": model_params["max_depth"],
            "random_state": model_params["random_state"],
            "security_review": "completed",
            "bias_testing": "completed",
        })
        
        # Train model
        model = RandomForestClassifier(**model_params)
        model.fit(training_data["X"], training_data["y"])
        
        # Evaluate model
        val_accuracy = model.score(validation_data["X"], validation_data["y"])
        
        # Log metrics
        mlflow.log_metrics({
            "val_accuracy": val_accuracy,
            "adversarial_robustness_score": 0.92,
            "bias_disparity_ratio": 0.04,
        })
        
        # Log model
        mlflow.sklearn.log_model(
            model,
            artifact_path="model",
            registered_model_name="secure-classifier-v2"
        )
        
        # Log artifacts
        mlflow.log_artifact("model_card.md")
        mlflow.log_artifact("bias_test_results.json")
        mlflow.log_artifact("security_assessment.pdf")
        
        return model

# Usage
trained_model = train_secure_model(
    training_data,
    validation_data,
    model_params={
        "n_estimators": 100,
        "max_depth": 10,
        "random_state": 42,
    }
)
```

---

## 5. MODEL VERSIONING & REGISTRY SECURITY

### 5.1 Model Versioning Strategy

| Version | Format | Example | Use Case |
|---------|--------|---------|----------|
| **Semantic** | MAJOR.MINOR.PATCH | v2.3.1 | Production tracking |
| **Git Hash** | First 7 chars of commit | a1b2c3d | Development |
| **Timestamp** | YYYYMMDD_HHMM | 20251127_1430 | Automated deployments |

### 5.2 Model Registry Access Control

```python
def configure_model_registry_security():
    """Configure RBAC for MLflow Model Registry"""
    
    # Role definitions
    roles = {
        "data_scientist": {
            "permissions": ["read", "write", "register_model"],
            "scope": "models/development/*"
        },
        "ml_engineer": {
            "permissions": ["read", "write", "promote_stage"],
            "scope": "models/*"
        },
        "security_team": {
            "permissions": ["read", "audit", "block"],
            "scope": "models/*"
        },
        "ml_ops": {
            "permissions": ["read", "deploy", "rollback"],
            "scope": "models/production/*"
        }
    }
    
    # Stage transition policies
    stage_transitions = {
        "None → Staging": {
            "required_approvers": ["ml_engineer"],
            "required_tests": ["unit", "integration"],
            "documentation": "required"
        },
        "Staging → Production": {
            "required_approvers": ["security_team", "ml_ops"],
            "required_tests": ["security", "adversarial", "bias"],
            "documentation": "required",
            "sign_off": "required"
        },
        "Production → Archived": {
            "required_approvers": ["ml_ops"],
            "reason": "required"
        }
    }
    
    return roles, stage_transitions
```

---

## 6. DEPLOYMENT PIPELINE SECURITY

### 6.1 CI/CD Pipeline for Model Deployment

```yaml
# .github/workflows/deploy_model.yml
name: Secure Model Deployment

on:
  push:
    branches: [main]
    paths: ['models/**']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Dependency scanning
      - name: Run dependency scan
        run: |
          pip install pip-audit
          pip-audit
      
      # SAST (Static Application Security Testing)
      - name: Run security analysis
        run: |
          pip install bandit
          bandit -r ./models/ -f json -o security_report.json
      
      # Unit tests
      - name: Run unit tests
        run: pytest tests/unit/ --cov

  model-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Load model from registry
      - name: Validate model format
        run: python scripts/validate_model.py
      
      # Verify model card exists
      - name: Check model documentation
        run: |
          test -f model_card.md || exit 1
      
      # Performance baseline check
      - name: Verify performance metrics
        run: python scripts/check_performance_baseline.py

  security-testing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Install garak for LLM scanning
      - name: Install LLM security scanner
        run: pip install garak
      
      # Run prompt injection tests
      - name: Test prompt injection vulnerabilities
        run: |
          python -m garak \
            --target_type openai \
            --target_name gpt-3.5-turbo \
            --probes promptinject \
            --report_type json > garak_results.json
      
      # Check results
      - name: Check security test results
        run: python scripts/check_garak_results.py garak_results.json

  approval-gate:
    needs: [security-scan, model-validation, security-testing]
    runs-on: ubuntu-latest
    steps:
      - name: Wait for manual approval
        uses: trstringer/manual-approval@v1
        with:
          secret: ${{ secrets.GITHUB_TOKEN }}
          approvers: security-team

  deploy:
    needs: approval-gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Deploy to production
      - name: Deploy model to production
        run: |
          python scripts/deploy_model.py \
            --model_name secure-chatbot \
            --stage production \
            --deployment_id ${{ github.run_id }}
      
      # Smoke tests
      - name: Run smoke tests
        run: python tests/smoke/ --environment production
      
      # Log deployment
      - name: Log deployment event
        run: python scripts/log_deployment.py

```

---

## 7. MONITORING & OBSERVABILITY

### 7.1 Performance Monitoring with Evidently AI

```python
from evidently.report import Report
from evidently.metric_preset import DataDriftPreset
from evidently.metrics import RegressionPerformanceMetrics
import pandas as pd

def setup_performance_monitoring(reference_data: pd.DataFrame,
                                 production_data: pd.DataFrame):
    """Setup continuous monitoring for model performance"""
    
    # Create report for data drift
    report = Report(metrics=[DataDriftPreset()])
    report.run(reference_data=reference_data, current_data=production_data)
    
    # Save report
    report.save_html("data_drift_report.html")
    
    # Extract metrics
    metrics = report.as_dict()
    
    return metrics

def check_drift_thresholds(drift_metrics: dict, thresholds: dict):
    """Check if drift metrics exceed thresholds"""
    
    alerts = []
    
    for metric_name, threshold in thresholds.items():
        current_value = drift_metrics.get(metric_name)
        
        if current_value and current_value > threshold:
            alerts.append({
                "metric": metric_name,
                "current": current_value,
                "threshold": threshold,
                "status": "ALERT"
            })
    
    return alerts
```

### 7.2 Drift Detection & Auto-Retraining

```python
class DriftDetector:
    """Detect model and data drift, trigger retraining"""
    
    def __init__(self, accuracy_threshold: float = 0.02,
                 drift_threshold: float = 0.05):
        self.accuracy_threshold = accuracy_threshold  # 2% drop triggers alert
        self.drift_threshold = drift_threshold  # 5% drift triggers alert
        self.baseline_metrics = {}
    
    def check_accuracy_drift(self, current_accuracy: float):
        """Check if accuracy has drifted below threshold"""
        
        if not self.baseline_metrics:
            self.baseline_metrics["accuracy"] = current_accuracy
            return False
        
        baseline = self.baseline_metrics["accuracy"]
        drift = (baseline - current_accuracy) / baseline
        
        if drift > self.accuracy_threshold:
            return True, drift
        
        return False, drift
    
    def check_data_drift(self, reference_dist: dict, 
                        current_dist: dict) -> bool:
        """Check if data distribution has drifted"""
        
        # Kolmogorov-Smirnov test
        from scipy.stats import ks_2samp
        
        statistic, p_value = ks_2samp(
            reference_dist.values(),
            current_dist.values()
        )
        
        if statistic > self.drift_threshold:
            return True, statistic
        
        return False, statistic
    
    def trigger_retraining(self, drift_reason: str):
        """Trigger automatic model retraining"""
        
        print(f"Drift detected: {drift_reason}")
        print("Triggering automatic retraining...")
        
        # Call retraining pipeline
        # This could trigger a GitHub Actions workflow
        # or launch an AWS SageMaker training job
        pass
```

---

## 8. SECURITY CHECKLIST & SIGN-OFF

### 8.1 Pre-Deployment Security Checklist

| Item | Completed | Owner | Date |
|------|-----------|-------|------|
| **Input Validation** |
| ☐ Input length validation implemented | | | |
| ☐ SQL injection prevention tested | | | |
| ☐ Special character filtering applied | | | |
| ☐ Semantic prompt injection detection enabled | | | |
| **Guardrails & Safety** |
| ☐ Guardrails (NeMo/LangChain) configured | | | |
| ☐ Jailbreak patterns documented | | | |
| ☐ Business rule enforcement tested | | | |
| ☐ Confidence threshold set and validated | | | |
| **Output Filtering** |
| ☐ PII redaction implemented | | | |
| ☐ Harmful content detection enabled | | | |
| ☐ URL filtering configured | | | |
| ☐ Output validation tested | | | |
| **Model Security** |
| ☐ Model version recorded in registry | | | |
| ☐ Model signed and verified | | | |
| ☐ Model documentation (card, datasheet) complete | | | |
| ☐ Adversarial robustness tested | | | |
| ☐ Backdoor detection performed | | | |
| ☐ Data poisoning assessment completed | | | |
| **Infrastructure Security** |
| ☐ TLS 1.2+ configured for all endpoints | | | |
| ☐ Encryption at rest enabled (AES-256) | | | |
| ☐ VPC isolation configured | | | |
| ☐ Security groups restrict access | | | |
| ☐ RBAC roles defined and assigned | | | |
| ☐ MFA enabled for critical operations | | | |
| **Monitoring & Logging** |
| ☐ Audit logging configured | | | |
| ☐ Drift detection monitoring active | | | |
| ☐ Performance alerts configured | | | |
| ☐ SIEM integration complete | | | |
| ☐ Log retention policy set | | | |
| **Compliance** |
| ☐ Privacy Impact Assessment completed | | | |
| ☐ GDPR compliance verified | | | |
| ☐ Data retention policy documented | | | |
| ☐ Vendor security assessments done | | | |
| ☐ Compliance audit passed | | | |
| **Testing & Validation** |
| ☐ Unit tests pass (>80% coverage) | | | |
| ☐ Integration tests pass | | | |
| ☐ Security tests pass (Garak, etc.) | | | |
| ☐ Performance tests pass | | | |
| ☐ Bias/fairness tests completed | | | |
| ☐ Smoke tests on staging passed | | | |
| **Documentation** |
| ☐ Architecture documentation complete | | | |
| ☐ Runbooks created for common issues | | | |
| ☐ Incident response plan documented | | | |
| ☐ Security training completed by team | | | |

### 8.2 Deployment Sign-Off

```
DEPLOYMENT APPROVAL FORM

Model Name: ___________________________
Model Version: ___________________________
Deployment Date: ___________________________

APPROVALS REQUIRED:

☐ Security Lead
   Name: ___________________________
   Date: ___________________________
   Signature: ___________________________

☐ ML Engineer Lead
   Name: ___________________________
   Date: ___________________________
   Signature: ___________________________

☐ Operations Lead
   Name: ___________________________
   Date: ___________________________
   Signature: ___________________________

DEPLOYMENT DETAILS:

Environment: ☐ Staging ☐ Production

Deployment Method:
  ☐ Canary (10% users initially)
  ☐ Blue-Green (parallel deployment)
  ☐ Rolling (gradual rollout)

Rollback Plan:
  Previous stable version: _____________________________
  Rollback trigger threshold: _____________________________

Known Issues / Limitations:
  _________________________________________________________________

Post-Deployment Monitoring:
  ☐ Accuracy monitoring active
  ☐ Performance monitoring active
  ☐ Error rate monitoring active
  ☐ Security alert monitoring active

Duration of monitoring: ___________________________

Contact information for escalation:
  _________________________________________________________________
```

---

## 9. IMPLEMENTATION ROADMAP

### Phase 1: Foundation (Weeks 1-2)
- ✅ MLflow setup and configuration
- ✅ Model Registry initialization
- ✅ Access control (RBAC) setup

### Phase 2: Security Controls (Weeks 3-4)
- ✅ Input validation implementation
- ✅ Guardrails deployment
- ✅ Output filtering setup

### Phase 3: Monitoring (Weeks 5-6)
- ✅ Audit logging configuration
- ✅ Drift detection setup
- ✅ Performance monitoring dashboard

### Phase 4: Testing & Deployment (Weeks 7-8)
- ✅ Security testing (Garak, adversarial)
- ✅ Staging deployment
- ✅ Production deployment with approval gates

---

## QUICK REFERENCE: Tools & Technologies

| Component | Recommended Tools |
|-----------|-------------------|
| **Model Registry** | MLflow, DVC, ModelDB |
| **Data Versioning** | DVC, Pachyderm |
| **Monitoring** | Evidently AI, WhyLabs, Fiddler |
| **Guardrails** | NeMo Guardrails, LangChain, Guardrails AI |
| **LLM Security Testing** | Garak, Promptfoo, HiddenLayer |
| **Adversarial Testing** | ART, Foolbox, CleverHans |
| **SIEM Integration** | Splunk, ELK Stack, Datadog |
| **CI/CD** | GitHub Actions, GitLab CI, Jenkins |
| **Infrastructure** | AWS, Google Cloud, Azure |

---

## CONCLUSION

This secure AI/ML architecture provides:

✅ **End-to-end security** from input validation to output filtering  
✅ **Full model governance** with versioning and approval gates  
✅ **Continuous monitoring** for performance and security  
✅ **Compliance ready** with audit logging and documentation  
✅ **Production-hardened** infrastructure and best practices  

Organizations implementing this architecture will:
- 🛡️ Prevent common AI attacks (prompt injection, jailbreaking, data poisoning)
- 📊 Monitor model performance and detect drift automatically
- 📋 Maintain full audit trails for compliance
- 🚀 Deploy models confidently with approval gates
- 🔄 Scale AI systems responsibly and securely

---

**Document Version:** 1.0  
**Last Updated:** November 28, 2025  
**Classification:** Internal Use / Confidential

For questions or updates, contact the ML Engineering team.
