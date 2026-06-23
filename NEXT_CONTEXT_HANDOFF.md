# Next Context Handoff

## Current Context
The architecture is now partially wired end to end:
- Gateway request flow has been changed to support prompt -> defenses -> model output -> SQL/template execution -> DB response.
- `DT` replaced `I6` in the gateway config and tests.
- Oracle logic, analysis scripts, red-team fixtures, and the audit trigger path were updated for the findings in `FINDINGS-AND-FIXES.md`.
- Static diagnostics on edited Python files were clean, but no runtime validation was possible in this environment.

The current task for the next context is to finish the surrounding experiment infrastructure so the thesis workflow is reproducible from a clean machine.

## What Is Already Done
- Gateway core behavior was updated in `gateway/app.py`, `gateway/db.py`, `gateway/config.py`, `gateway/defense_a.py`, `gateway/defense_b.py`.
- DT template execution was added in `gateway/templates.py`.
- Oracle detection logic was updated in `oracle/canary.py`, `oracle/state_diff.py`, `oracle/correlate.py`, `oracle/db_log.py`.
- Analysis scripts now load artifacts instead of hardcoded demo data in `analysis/stats.py` and `analysis/plots.py`.
- Red-team corpus was normalized to English and `blocked` / `allowed` in `redteam/attacks/*.yaml`, `redteam/legit_set.yaml`, `redteam/promptfooconfig.yaml`, and `validate_step6.sh`.
- Tests were refreshed in `test_gateway.py` and `test_modules.py`.

## What Is Still Missing
### 1. Reproducible Postgres bootstrap
There is no one-command setup that:
- creates the `marketplace` database,
- loads `db/01_schema.sql` through `db/07_canary.sql` in the correct order,
- applies `log_statement = 'all'`,
- reloads PostgreSQL config,
- and verifies the resulting role / RLS / masking state.

### 2. Environment bootstrap for the whole stack
There is still no single documented path that brings up:
- PostgreSQL,
- the gateway,
- the target model endpoint,
- and the analysis tooling with matching environment variables.

### 3. Prompt corpus and promptfoo execution harness
The repo has the red-team config and the legit set, but it still needs:
- a clean prompt library for normal / valid prompts,
- a per-layer execution workflow for D0, DA, DB, DC-a, DC-b, DC-c, D++, and DT,
- artifact tagging and collection for later analysis,
- and a documented run sequence that a fresh context can follow without guessing.

### 4. Garak baseline wiring
The baseline script and config exist, but they still need confirmation or repair so they actually run against the intended local model setup and produce usable artifacts.

### 5. Documentation sync
Some docs still mention the old `I6` naming or contain older workflow wording. The code is mostly aligned, but the docs need a final sweep so the terminology is consistent everywhere.

## Recommended Next Task
Build the missing orchestration layer first. The best next implementation slice is:

1. Create a single bootstrap script or makefile/task that provisions PostgreSQL, loads the schema/seed/canary files, enables logging, and verifies the DB role posture.
2. Add a single run script for the gateway plus local model endpoint.
3. Add a red-team runner that executes promptfoo once per layer and saves tagged artifacts.
4. Add a matching garak runner that targets the same model endpoint and produces baseline artifacts.
5. Update the docs to describe the exact run order and outputs.

## Files To Inspect First
- `db/README.md`
- `setup.sh`
- `setup_gateway.sh`
- `run_garak_baseline.sh`
- `garak_config.yaml`
- `redteam/promptfooconfig.yaml`
- `redteam/legit_set.yaml`
- `validate_step6.sh`
- `analysis/stats.py`
- `analysis/plots.py`

## Constraints For The Next Context
- Do not assume runtime verification is available unless you first add or use a local toolchain.
- Keep the scope focused on orchestration and reproducibility.
- Prefer one new setup path over many ad hoc commands.
- Preserve the English-only rule for all new user-facing text and comments.

## Success Criteria
The next context should be able to answer yes to all of these:
- Can I provision the DB from scratch with one documented command path?
- Can I start the gateway and model in a reproducible way?
- Can I run promptfoo per layer and collect artifacts?
- Can I run garak baseline and collect artifacts?
- Can analysis consume those artifacts without manual reshaping?
