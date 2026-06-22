# Gateway

This directory contains the FastAPI gateway implementation for the LLM security evaluation.

## Files

- `app.py` - Main FastAPI application with routing and middleware
- `identity.py` - Identity propagation from LDAP/AD or auth tokens
- `defense_a.py` - System prompt hardening (Defense A)
- `defense_b.py` - Input guardrail (Defense B)
- `config.py` - Configuration management for security layers
- `requirements.txt` - Python dependencies

## Security Features Implemented

1. **Authentication & Identity Propagation**: 
   - Extracts tenant/role from auth headers
   - Prevents identity from being derived from prompts

2. **Defense A (System Prompt Hardening)**:
   - Hardens system prompts against jailbreak attempts
   - Enforces security constraints in prompt engineering

3. **Defense B (Input Guardrail)**:
   - Filters potentially unsafe inputs
   - Prevents prompt injection attacks

4. **Trace ID & Latency Logging**:
   - Unique trace IDs for each request
   - Server-side latency measurements

5. **Configurable Security Layers**:
   - D0: No defenses
   - DA: Defense A (System Prompt)
   - DB: Defense B (Input Guardrail)
   - DC-a/b/c: Data confidentiality layers
   - I6: Template-based operations