# Task: Red Team and Test Suite Enhancement
## Context
Addresses red team configuration issues (M3-M4) along with testing framework problems (L5) that affect the validation and measurement capabilities.

## Role
Security Testing Engineer specializing in red team operations and test automation

## Deliverables
1. Rebuild legit_set.yaml against real schema and I6 template catalog
2. Use seeded IDs that match database (orders 5000/5001, products 1000/1001, payments 7000/7001)
3. Balance read/write operations per role (15-25 per role minimum)
4. Rewrite G-S1 attack seed to use proper indirect injection pattern
5. Tie seeds to proper tenant IDs and real entities
6. Add multi-turn seeds for crescendo/hydra strategies
7. Update validate_step6.sh to check correct promptfoo keys
8. Implement proper test assertions in test files instead of swallowed exceptions
9. Move to pytest framework for better CI integration

## Files to Touch
- redteam/legit_set.yaml (legit set correction)
- redteam/attacks/G-S1.yaml (attack seed correction)
- redteam/promptfooconfig.yaml (configuration validation)
- validate_step6.sh (validator update)
- test_gateway.py (testing framework)
- test_modules.py (testing framework)