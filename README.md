# Defense‑in‑Depth LLM Evaluation

This repository provides a full stack for evaluating LLM security layers using a PostgreSQL backend, a FastAPI gateway, **Garak** baseline tests, and **Promptfoo** red‑team testing.

---

## Prerequisites

- **Python 3.8+** (the scripts will pick the first `python`, `python3`, or `py` on your `$PATH`).
- **Node.js / npm** – required only for the global `promptfoo` installation.
- **PostgreSQL 16** client tools (`psql`, `createdb`, `dropdb`). The database must be reachable on `localhost:5432` (or configure `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`).
- **vLLM** (installable via `pip install vllm` or provided in your environment) – the model server.
- **Garak** (`pip install garak`) – used for baseline attacks.
- **Git** – scripts use it to embed the current commit SHA in Promptfoo runs.

> The top‑level `setup.sh` script will install the required Python packages and `promptfoo` globally, and create the necessary runtime directories.

---

## Quick‑Start Order

1. **Initial environment setup**
   ```bash
   ./setup.sh            # installs Python deps, promptfoo, creates dirs
   ```
   *Optional flags:* `--skip-db` to avoid bootstrapping the DB, `--skip-gateway` to skip the gateway virtual‑env creation.

2. **Bootstrap the PostgreSQL database**
   ```bash
   ./bootstrap_db.sh     # creates the "marketplace" DB and applies schema
   ```
   This step loads the schema in the required order (grants → RLS → masking) and enables statement logging.

3. **Start the full stack (model server + gateway)**
   ```bash
   ./run_stack.sh        # launches vLLM and the FastAPI gateway
   ```
   The script starts `vllm` on port **8001** and the gateway on **8000**. Logs are written to `runs/stack/<timestamp>/`.
   The command blocks; keep it running in a terminal or in the background.

4. **Run the Garak baseline tests**
   ```bash
   ./run_garak_baseline.sh
   ```
   Results are stored under `analysis/artifacts/garak/<run-id>/` and the raw Garak output is copied to `garak_results/`.

5. **Run Promptfoo layer tests**
   ```bash
   ./run_promptfoo_layers.sh
   ```
   This executes the red‑team generation + evaluation for each security layer (D0, DA, DB, DC‑a, DC‑b, DC‑c, D++, DT). Artifacts are placed in `analysis/artifacts/promptfoo/<run-id>/`.

6. **Validate the Red‑Team configuration (optional)**
   ```bash
   ./validate_step6.sh
   ```
   Performs a quick sanity‑check of the `redteam/` YAML files.

---

## Environment Variables (override defaults)
| Variable | Default | Purpose |
|---|---|---|
| `GATEWAY_HOST` | `127.0.0.1` | Host for the FastAPI gateway |
| `GATEWAY_PORT` | `8000` | Port for the gateway |
| `VLLM_HOST` | `0.0.0.0` | Host for the vLLM server |
| `VLLM_PORT` | `8001` | Port for the vLLM server |
| `TARGET_MODEL` | `Qwen/Qwen3-14B` | Model name passed to `vllm serve` |
| `VLLM_API_KEY` | `token-abc123` | API key required by vLLM |
| `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` | `localhost`, `5432`, `postgres`, (empty) | PostgreSQL connection settings |
| `DB_NAME` | `marketplace` | Database name created by `bootstrap_db.sh` |
| `GARAK_CONFIG` | `garak_config.yaml` | Garak configuration file |
| `PROMPTFOO_CONFIG` | `redteam/promptfooconfig.yaml` | Promptfoo configuration |

---

## Project Layout (relevant directories)
- `gateway/` – FastAPI gateway source and its virtual environment (`venv`).
- `db/` – SQL schema files and documentation.
- `redteam/` – Promptfoo configuration, legitimate request set, and attack YAMLs.
- `analysis/artifacts/` – Stores Promptfoo and Garak results per run.
- `runs/stack/` – Logs for the model server and gateway.

---

## Tips
- Run `./setup.sh` **once**; it is idempotent.
- If you need to experiment with different security layers, edit the SQL files in `db/` or use the provided teardown scripts.
- Use `./validate_step6.sh` after modifying any red‑team YAML to ensure correct structure.
- All scripts exit on error (`set -euo pipefail`), so any failure will stop the pipeline.

---

## License

[MIT License](LICENSE) (or as defined in the repository).
