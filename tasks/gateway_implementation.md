# Task: Secure Gateway Implementation
## Context
Addresses critical gateway functionality issues (C4) along with defense mechanism problems (M1-M2) that all relate to the core gateway functionality.

## Role
Security Gateway Engineer specializing in LLM integrations and defense mechanisms

## Deliverables
1. Complete LLM integration with vLLM endpoint for SQL generation
2. Implement complete transaction flow with role setting and identity propagation
3. Execute generated SQL within proper database transactions
4. Tag DB sessions with trace-id for Oracle correlation
5. Fix Defense A implementation with proper hardened system prompt application
6. Enhance Defense B with tighter injection-specific patterns
7. Add proper latency measurements (TTFT + end-to-end)
8. Ensure all security layers work together in the gateway

## Files to Touch
- gateway/app.py (main gateway implementation)
- gateway/db.py (database transaction handling)
- gateway/defense_a.py (defense A enhancement)
- gateway/defense_b.py (defense B enhancement)
- gateway/config.py (configuration settings)
- gateway/identity.py (identity propagation)