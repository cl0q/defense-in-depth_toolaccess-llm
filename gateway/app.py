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
import requests
from typing import Optional
from pydantic import BaseModel
import os

from .identity import get_current_identity, get_mock_identity
from .defense_a import apply_defense_a, get_hardened_system_prompt
from .defense_b import apply_defense_b
from .config import get_config
from .db import execute_transaction

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
    ttft_ms: float  # Time to first token

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

def get_trace_id(request: Request) -> str:
    return getattr(request.state, "trace_id", "")

@app.post("/query", response_model=QueryResponse)
async def process_query(
    request: QueryRequest,
    identity: dict = Depends(get_current_identity),
    trace_id: str = Depends(get_trace_id)
):
    """
    Main endpoint for processing queries through the LLM with security defenses
    """
    logger.info(f"Processing query for tenant {identity.get('tenant', 'unknown')}")
    
    # Apply Defense A: System Prompt Hardening
    if CONFIG.layer_da:
        # Use a more robust system prompt hardening approach
        # Generate a hardened system prompt combining security constraints
        base_prompt = "You are a helpful AI assistant designed to help with database queries."
        hardened_system_prompt = get_hardened_system_prompt(base_prompt)
        enhanced_prompt = f"{hardened_system_prompt}\n\nUser query: {request.prompt}"
    else:
        enhanced_prompt = request.prompt
    
    # Apply Defense B: Input Guardrail
    if CONFIG.layer_db:
        # This would integrate with LlamaGuard or similar
        guardrail_result = apply_defense_b(enhanced_prompt)
        if not guardrail_result["is_safe"]:
            raise HTTPException(status_code=400, detail=f"Input blocked by guardrail: {guardrail_result['reason']}")
    
    # Log with trace ID for Oracle correlation
    logger.info(f"Trace ID {trace_id}: Processing query for tenant {identity.get('tenant', 'unknown')}")
    
    # Measure latency for TTFT and end-to-end
    start_time = time.time()
    ttft_start = time.time()
    
    # Integrate with target LLM (vLLM endpoint)
    llm_response = ""
    llm_call_duration = 0
    try:
        # Prepare the payload for the vLLM endpoint
        payload = {
            "prompt": enhanced_prompt,
            "temperature": CONFIG.llm_temperature,
            "max_tokens": 500
        }
        
        # Make request to LLM endpoint
        llm_start_time = time.time()
        response = requests.post(
            CONFIG.llm_endpoint,
            json=payload,
            timeout=30  # 30 second timeout
        )
        llm_end_time = time.time()
        llm_call_duration = (llm_end_time - llm_start_time) * 1000
        
        if response.status_code == 200:
            llm_data = response.json()
            llm_response = llm_data.get("choices", [{}])[0].get("text", "").strip()
            
            # Calculate TTFT (Time To First Token)
            ttft_end = time.time()
            ttft_ms = (ttft_end - ttft_start) * 1000
        else:
            logger.error(f"LLM endpoint error: {response.status_code} - {response.text}")
            raise HTTPException(status_code=500, detail="Failed to get response from LLM")
            
    except requests.RequestException as e:
        logger.error(f"LLM request failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to communicate with LLM endpoint")
    
    # Execute SQL operations based on the LLM response
    # Note: In a real implementation, this would parse the LLM response for SQL commands
    # For demonstration, we'll execute a simple query and then log the results
    sql_statements = [
        "SELECT version();",
    ]
    
    sql_execution_duration = 0
    try:
        # Execute transaction with proper identity propagation and trace-id tagging
        sql_start_time = time.time()
        results = execute_transaction(sql_statements, [], identity)
        sql_end_time = time.time()
        sql_execution_duration = (sql_end_time - sql_start_time) * 1000
        
        logger.info(f"DB query results: {results}")
        
        # Include the SQL results in the response if needed
        llm_response += f"\n\nDatabase results: {results}" if results else ""
    except Exception as e:
        logger.error(f"DB execution failed: {e}")
        # Continue with LLM response even if DB fails
    
    end_time = time.time()
    total_latency_ms = (end_time - start_time) * 1000
    
    # Return enhanced response with both total and TTFT latencies
    return QueryResponse(
        response=llm_response,
        trace_id=trace_id,
        latency_ms=total_latency_ms,
        ttft_ms=ttft_ms if 'ttft_ms' in locals() else 0
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)