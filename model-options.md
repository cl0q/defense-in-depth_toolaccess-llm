# Model Options — Attacker vs. Victim

Two-model topology on a single **H200 (141 GB VRAM)**. The repo defines two roles:

- **Attacker** — generates jailbreaks (promptfoo: crescendo, hydra, meta strategies).
  Pure text generation, no tool-calling. Wired in `redteam/promptfooconfig.yaml`
  (`provider:` + `PROMPTFOO_ATTACKER_BASE_URL`).
- **Victim / target** — the marketplace assistant under test. Receives the hardened
  system prompt + user query and emits SQL / fills templates against the DB.
  Needs tool-calling. Wired through the gateway → vLLM (`run_stack.sh`, port 8001),
  and baselined directly by garak (`garak_config.yaml`).

VRAM rule (from `vllm-serving-manual.md`): `Σ(gpu-memory-utilization) ≲ 0.95`,
leave ~7 GB headroom. VRAM = weights + KV cache. FP8 ≈ 1 GB per 1B params.

Context sizing: neither role needs long context. Victim use is system prompt +
schema/few-shot + one query → emit SQL (~2–6K tokens real). Attacker convos are
short even for multi-turn crescendo. **32K (`--max-model-len 32768`) is generous
headroom for both** and keeps each model's KV cache to ~10–15 GB.

---

## Option 1 — Strong Attacker x Weak Victim  ✅ (start here)

**Thesis angle:** Does defense-in-depth hold against the strongest realistic adversary?

| Role | Model | HF ID | Port | `--gpu-memory-utilization` | `--max-model-len` |
|------|-------|-------|------|----------------------------|-------------------|
| **Attacker** | Hermes 4 70B FP8 | `NousResearch/Hermes-4-70B-FP8` | 8002 | `0.62` | `32768` |
| **Victim** | Qwen3.6 27B FP8 | `Qwen/Qwen3.6-27B-FP8` | 8001 | `0.28` | `32768` |

**VRAM:** ~70 + ~28 + KV cache ≈ 127 GB / 141 → ~14 GB headroom.

**Why these:**
- Hermes is low-refusal by design — it actually generates attacks instead of
  refusing them. A safety-tuned 70B would sabotage the red-team runs (promptfoo
  itself warns aligned models refuse to red-team).
- Qwen3.6-27B is a capable, realistic production-grade chat + tool-use model —
  represents a real deployed assistant.
- Both FP8 / same CUDA toolchain → no toolchain surprises.
- Qwen-family victim → `--tool-call-parser qwen3_xml` + `--reasoning-parser qwen3`
  work out of the box.

---

## Option 2 — Weak Attacker x Strong Victim

**Thesis angle:** Can a capable model exfiltrate data even under unsophisticated
attacks? Does model intelligence compensate for (or undermine) the defenses?

| Role | Model | HF ID | Port | `--gpu-memory-utilization` | `--max-model-len` |
|------|-------|-------|------|----------------------------|-------------------|
| **Attacker** | Qwen3 8B FP8 | `Qwen/Qwen3-8B-FP8` | 8002 | `0.08` | `32768` |
| **Victim** | Qwen3.6 72B FP8 | `Qwen/Qwen3.6-72B-FP8` | 8001 | `0.58` | `32768` |

**VRAM:** ~8 + ~72 + KV cache ≈ 95 GB / 141 → ~46 GB headroom (loads fast, lots of room).

**Why these:**
- 72B FP8 victim: strong open model — realistic "we deployed our best model" scenario.
- 8B attacker: unsophisticated adversary (script-kiddie level). Tests whether a
  smart-enough victim bypasses its own defenses without a clever attacker.
- Stays all-Qwen → same parsers, same venv, only served names + VRAM numbers change.

---

## What changes between runs (env vars only, no code edits)

| | Option 1 | Option 2 |
|---|----------|----------|
| `TARGET_MODEL` (victim) | `Qwen/Qwen3.6-27B-FP8` | `Qwen/Qwen3.6-72B-FP8` |
| `VLLM_SERVED_MODEL_NAME` | `qwen3-27b` | `qwen3-72b` |
| Attacker model | `NousResearch/Hermes-4-70B-FP8` | `Qwen/Qwen3-8B-FP8` |
| `PROMPTFOO_ATTACKER_BASE_URL` | `http://127.0.0.1:8002/v1` | `http://127.0.0.1:8002/v1` |
| victim `--gpu-memory-utilization` | `0.28` | `0.58` |
| attacker `--gpu-memory-utilization` | `0.62` | `0.08` |

---

## Launch commands (Option 1)

Launch **sequentially**, each in its own tmux. Wait for the victim's
"Application startup complete" before starting the attacker so the JIT compilers
don't stack RAM (the OOM trap in `vllm-serving-manual.md`).

**Victim first** (port 8001 — gateway + garak target this):

```bash
tmux new -s vllm-victim
export MAX_JOBS=4 NVCC_THREADS=1 VLLM_DEEP_GEMM_WARMUP=skip
vllm serve Qwen/Qwen3.6-27B-FP8 \
  --host 0.0.0.0 --port 8001 --served-model-name qwen3-27b \
  --api-key token-abc123 \
  --max-model-len 32768 --gpu-memory-utilization 0.28 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager --enable-auto-tool-choice \
  --tool-call-parser qwen3_xml --reasoning-parser qwen3
# wait for "Application startup complete" -> Ctrl-b d to detach
```

**Then attacker** (port 8002 — text only, no tool parser needed):

```bash
tmux new -s vllm-attacker
export MAX_JOBS=4 NVCC_THREADS=1 VLLM_DEEP_GEMM_WARMUP=skip
vllm serve NousResearch/Hermes-4-70B-FP8 \
  --host 0.0.0.0 --port 8002 --served-model-name hermes-70b \
  --api-key token-abc123 \
  --max-model-len 32768 --gpu-memory-utilization 0.62 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager
```

Verify each: `curl http://localhost:8001/v1/models` and `:8002/v1/models`.

## Wiring touchpoints

Three files reference the model endpoints — keep them matched to the table above:

1. `run_stack.sh` — victim `TARGET_MODEL` / `VLLM_SERVED_MODEL_NAME` / port 8001.
2. `garak_config.yaml` — `plugins.target_name` = victim served name (garak baselines
   the victim on 8001).
3. `redteam/promptfooconfig.yaml` — attacker `provider: openai:chat:<served-name>`,
   run with `PROMPTFOO_ATTACKER_BASE_URL=http://127.0.0.1:8002/v1`.
