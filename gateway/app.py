"""
FastAPI Gateway for LLM with Authentication, Identity Propagation,
Defense A/B, Trace-ID, and Latency Logging.
"""

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.cors import CORSMiddleware
import logging
import time
import uuid
from typing import Optional
from pydantic import BaseModel
import os

from .identity import get_current_identity
from .defense_a import apply_defense_a
from .defense_b import apply_defense_b
from .config import get_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="LLM Gateway",
    description="API Gateway for LLM with security defenses",
    version="0.1.0"
)

# Add middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Configuration
CONFIG = get_config()

class QueryRequest(BaseModel):
    prompt: str
    # Add other fields as needed

class QueryResponse(BaseModel):
    response: str
    trace_id: str
    latency_ms: float

@app.middleware("http")
async def add_trace_id(request: Request, call_next):
    """Add trace ID to each request"""
    trace_id = str(uuid.uuid4())
    request.state.trace_id = trace_id
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    response.headers["X-Trace-ID"] = trace_id
    response.headers["X-Process-Time"] = f"{process_time:.2f}ms"
    
    return response

@app.post("/query", response_model=QueryResponse)
async def process_query(
    request: QueryRequest,
    identity: dict = Depends(get_current_identity),
    trace_id: str = Depends(lambda request: getattr(request.state, 'trace_id', None))
):
    """
    Main endpoint for processing queries through the LLM with security defenses
    """
    logger.info(f"Processing query for tenant {identity.get('tenant', 'unknown')}")
    
    # Apply Defense A: System Prompt Hardening
    if CONFIG.defense_a_enabled:
        enhanced_prompt = apply_defense_a(request.prompt)
    else:
        enhanced_prompt = request.prompt
    
    # Apply Defense B: Input Guardrail
    if CONFIG.defense_b_enabled:
        # This would integrate with LlamaGuard or similar
        guardrail_result = apply_defense_b(enhanced_prompt)
        if not guardrail_result["is_safe"]:
            raise HTTPException(status_code=400, detail=f"Input blocked by guardrail: {guardrail_result['reason']}")
    
    # Log with trace ID for Oracle correlation
    logger.info(f"Trace ID {trace_id}: Processing query for tenant {identity.get('tenant', 'unknown')}")
    
    # Simulate LLM processing with latency measurement
    start_time = time.time()
    
    # TODO: Integrate with target LLM (vLLM endpoint)
    # This is a placeholder for actual LLM call
    llm_response = f"Processed response to: {enhanced_prompt}"
    
    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000
    
    # TODO: Execute SQL operations here based on the request
    
    return QueryResponse(
        response=llm_response,
        trace_id=trace_id,
        latency_ms=latency_ms
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)