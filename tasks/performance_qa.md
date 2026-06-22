# Task: Performance and Quality Assurance
## Context
Addresses latency measurement issues (L4) and overall quality assurance concerns (L5) that impact the system's usability and reliability.

## Role
Performance and QA Engineer specializing in system optimization and testing

## Deliverables
1. Implement proper latency measurements (TTFT + end-to-end)
2. Separate Defense-B model call latency reporting
3. Add proper timing to LLM calls and SQL execution
4. Implement comprehensive test suite with real assertions
5. Ensure tests can run successfully after all fixes
6. Fix existing test files that have swallowed exceptions
7. Improve overall system reliability and error handling
8. Ensure all measurements are accurate and meaningful

## Files to Touch
- gateway/app.py (latency measurement implementation)
- gateway/db.py (timing integration)
- test_gateway.py (test suite improvement)
- test_modules.py (test suite improvement)
- validate_step6.sh (ensure proper validation)