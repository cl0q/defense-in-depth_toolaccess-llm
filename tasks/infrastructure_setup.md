# Task: Infrastructure and Reproducibility Setup
## Context
Addresses infrastructure and reproducibility issues (L1-L3) that are essential for the research methodology and deployment consistency.

## Role
DevOps Engineer specializing in research reproducibility and infrastructure setup

## Deliverables
1. Create models.lock with pinned HF revisions and versions for all components
2. Add setup.sh with all required initialization steps for the complete system
3. Pin target model (Qwen3-14B) and attacker model consistently across all environments
4. Include quantization settings and seeds in reproducibility artifacts
5. Make garak paths relative to script location
6. Verify correct probe ids (dan, promptinject, etc.) for garak integration
7. Fix potential conflicts between CLI args and config file for garak
8. Update README paths to reflect correct locations

## Files to Touch
- models.lock (new file for reproducibility)
- setup.sh (new file for initialization)
- run_garak_baseline.sh (script to fix)
- garak_config.yaml (configuration to verify)
- redteam/README.md (documentation to update)
- db/README.md (documentation to verify)