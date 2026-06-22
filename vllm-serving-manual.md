# vLLM Serving Manual (H200 / 64 GB RAM box)

A practical guide for safely launching vLLM on a machine with a big GPU but
**limited host RAM (64 GB)**. Written after debugging repeated OOM kills.

---

## The core problem we hit

The OS OOM-killer kept killing the loader. The culprit was **NOT** model
weights or VRAM — it was the **CUDA kernel JIT compiler (`cicc`/`nvcc`)**.

FP8 models (DeepGEMM / FlashInfer / GDN) **compile GPU kernels at startup** and
parallelize the compile across **all CPU cores**. With 40 cores that meant
~40 compiler processes × ~1.5–2 GB each ≈ **60–80 GB → instant OOM**.

`dmesg` confirmed it: `Killed process NNNN (cicc)`.

### The fix (the single most important thing)
Throttle compilation so it fits in RAM:

```bash
export MAX_JOBS=4          # max parallel nvcc/cicc processes (default = all cores)
export NVCC_THREADS=1      # threads per nvcc
```

`MAX_JOBS=4` keeps peak compile RAM around ~8–12 GB. Raise/lower to taste:
roughly `MAX_JOBS × 2 GB` is your compile RAM budget.

---

## Required environment variables

```bash
# --- CUDA toolchain ---
export CUDA_HOME=/usr/local/cuda
export PATH=$CUDA_HOME/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:${LD_LIBRARY_PATH:-}

# --- THE RAM FIX: throttle kernel compilation ---
export MAX_JOBS=4
export NVCC_THREADS=1
export VLLM_DEEP_GEMM_WARMUP=skip   # skip the heavy FP8 warmup compile sweep

# --- Optional but recommended ---
export HF_TOKEN=hf_xxx               # avoids rate-limited/slow HF downloads
# export VLLM_USE_DEEP_GEMM=0        # NUCLEAR OPTION: disable DeepGEMM JIT entirely
# export VLLM_MOE_USE_DEEP_GEMM=0    #   (use if compile still OOMs; slightly slower FP8)
```

---

## Key vLLM CLI args explained

| Arg | What it does | Recommendation |
|-----|--------------|----------------|
| `--load-format runai_streamer` | Streams weights to GPU through a **bounded** CPU buffer instead of loading the whole checkpoint into RAM. | Always use on low-RAM boxes. |
| `--model-loader-extra-config '{"memory_limit": 4294967296}'` | Caps that CPU staging buffer (here 4 GB). | Keep 4–8 GB. |
| `--gpu-memory-utilization 0.90` | Fraction of VRAM vLLM may use (weights + KV cache). | 0.90 leaves headroom. Lower if you run multiple models. |
| `--max-model-len 32768` | Max context length. Bigger = more KV cache VRAM. | Match your needs. |
| `--max-num-seqs 64` | Max concurrent sequences. | 32–64 is fine. |
| `--enforce-eager` | **Disables CUDA graphs + torch.compile.** Removes a startup variable and saves a little VRAM, at ~10–20% throughput cost. | Keep ON while stabilizing. Drop later for speed. |
| `--gdn-prefill-backend triton` | Skips the FlashInfer GDN JIT compile (one of the slow startup steps). | Try it to cut startup time. |

### About CUDA graphs (`--enforce-eager`)
CUDA graphs are a **speed optimization** (pre-record GPU execution to cut
per-token launch overhead). They cost a little extra VRAM + startup time but
**zero extra host RAM**. They were never the cause of the OOM. Keep
`--enforce-eager` until everything is stable, then remove it to regain speed.

---

## Golden launch command

```bash
vllm serve Qwen/Qwen3.6-27B-FP8 \
  --host 0.0.0.0 --port 8000 \
  --max-model-len 65536 \
  --gpu-memory-utilization 0.90 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager \
  --max-num-seqs 64 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_xml \
  --reasoning-parser qwen3
```

`--enable-auto-tool-choice` + `--tool-call-parser qwen3_xml` are **required** for
AI coding tools (OpenCode, Continue, etc.) which send `tool_choice: "auto"` on
every request. Without them you get `400 Bad Request` errors and the client
can't use tools (file editing, search, etc.).

**Parser choice matters — Qwen3.6 emits XML-style tool calls**, e.g.
`<tool_call><function=run_command><parameter=command>ls</parameter></function></tool_call>`.
The `hermes` parser expects JSON inside `<tool_call>` and will throw
`JSONDecodeError: Expecting value` (visible in the vLLM log), silently dropping
the call into `content` with an empty `tool_calls` array — tools appear "broken."
Use **`qwen3_xml`** (or `qwen3_coder`, same underlying parser) for this model.
Use `hermes` only for models that emit JSON tool calls.

`--reasoning-parser qwen3` separates Qwen3's `<think>` chain-of-thought into a
dedicated response field so clients hide it correctly. Without it, raw "Thinking
Process" text leaks into the UI (e.g. during OpenCode's compaction step).

`--max-model-len 65536`: Qwen3 supports large context. With ~95 GB free KV
cache on the H200 you can easily afford 64K. Too small a value causes clients
to hit "maximum context length" errors and triggers pointless auto-compaction
loops (the client thinks every message overflows). Match this to the `context`
limit in your client config (see OpenCode section).

---

## Operational rules (learned the hard way)

1. **Never run with `sudo`.** It puts the HF model cache and the compiled-kernel
   cache in `/root/.cache`. Run as your normal user so caches live in
   `~/.cache` and **persist across restarts** (the 25-min first-start compile
   only happens once).
2. **Always run inside `tmux`** so an SSH disconnect (closed laptop lid, wifi
   drop, idle timeout) doesn't kill the server:
   ```bash
   tmux new -s vllm          # start
   #   ... launch vllm ...
   # Ctrl+B then D           # detach (server keeps running)
   tmux attach -t vllm       # reattach later
   ```
3. **First start is slow (~25 min), restarts are fast.** The slow part is JIT
   kernel compilation; results are cached in `~/.cache`. Don't kill it thinking
   it hung — watch RAM/`cicc` count instead.
4. **Verify it's up:**
   ```bash
   curl http://localhost:8000/v1/models
   curl http://localhost:8000/health
   ```
5. **If it still OOMs during compile:** lower `MAX_JOBS` (e.g. `2`), or set
   `VLLM_USE_DEEP_GEMM=0` + `VLLM_MOE_USE_DEEP_GEMM=0` to skip DeepGEMM JIT.

---

## Diagnosing an OOM (which kind is it?)

Two opposite problems — check `dmesg` to tell them apart:

```bash
sudo dmesg | grep -i -E "killed process|out of memory" | tail -25
```

- Killed `cicc` / `nvcc`  → **compile RAM** → lower `MAX_JOBS`.
- Killed `VLLM` / `EngineCore`, or no dmesg + a `CUDA out of memory` Python
  traceback → **VRAM** → lower `--gpu-memory-utilization` or `--max-model-len`.

Monitor live in a second pane:
```bash
watch -n2 'free -h; echo; nvidia-smi --query-gpu=memory.used,memory.total --format=csv; echo; echo cicc=$(pgrep -c cicc)'
```

---

## VRAM budgeting for multiple models

### First: understand what "130 GB used" means

vLLM **pre-allocates VRAM at startup** based on `--gpu-memory-utilization`. It
grabs that whole slice immediately and holds it whether you serve 1 request or
100 — this is by design (no mid-request allocation = fast & predictable).

```
VRAM reserved = gpu-memory-utilization × total VRAM
0.90 × 143 GB ≈ 129 GB
```

That reserved block is split into:
- **Model weights** — fixed (~28 GB for Qwen3.6-27B-FP8).
- **KV cache** — everything left over after weights. More KV cache = more
  concurrent requests and longer contexts, but past a point it's wasted.
- **Activations / overhead** — small.

So 130 GB is NOT the model being huge — it's mostly KV cache vLLM grabbed
because you told it it could use 90% of the GPU. Lower the number to reserve
less.

### The budgeting rule

```
Σ (gpu-memory-utilization of all models)  ≲  0.95
```

Leave ~5% (≈7 GB) unreserved as headroom. Plan each model's fraction so they
sum to at most ~0.95. Each model needs `weights + some KV cache` to fit in its
slice, so never set a fraction so low it can't hold the weights.

### Reference table (143 GB H200, 27B-FP8 ≈ 28 GB weights)

| Setup | `--gpu-memory-utilization` | VRAM each | KV cache each |
|-------|----------------------------|-----------|---------------|
| 1 model, max throughput | `0.90` | ~129 GB | ~95 GB (overkill for coding) |
| 1 model, sane | `0.45` | ~64 GB | ~30 GB (plenty) |
| **2 models in parallel** | `0.45` + `0.45` | ~64 GB each | ~30 GB each |
| 27B + small (e.g. 7B) | `0.45` + `0.20` | 64 GB / 29 GB | comfortable |
| 3 models | `0.30` each | ~43 GB each | tight but works for small ctx |

> Rule of thumb: for coding work you rarely need more than ~20–30 GB of KV
> cache. Giving a single model 95 GB is wasteful — reclaim it for other models.

### Per-model rules

- **Each model needs its own `--port`** (8000, 8001, 8002, ...).
- **Run each in its own tmux session** (`tmux new -s vllm-27b`, `-s vllm-7b`).
- **Set `gpu-memory-utilization` so the fractions sum to ≲ 0.95.**
- **Launch them SEQUENTIALLY**, not at once. Two simultaneous startups both
  spawn JIT compilers (`cicc`) and stack their RAM usage → risk of the original
  OOM. Let model #1 fully finish loading, THEN start model #2. `MAX_JOBS=4`
  is global, so concurrent compiles also just fight for CPU.

### Concrete two-model example

**Session 1 — the 27B (primary), 45% of VRAM:**
```bash
tmux new -s vllm-27b
# (set env vars: CUDA, MAX_JOBS=4, etc.)
vllm serve Qwen/Qwen3.6-27B-FP8 \
  --host 0.0.0.0 --port 8000 \
  --max-model-len 65536 \
  --gpu-memory-utilization 0.45 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager \
  --max-num-seqs 64 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_xml \
  --reasoning-parser qwen3
# Ctrl-b d to detach. WAIT for "Application startup complete" first.
```

**Session 2 — a smaller model, 20% of VRAM, on port 8001:**
```bash
tmux new -s vllm-small
# (same env vars)
vllm serve <small-model> \
  --host 0.0.0.0 --port 8001 \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.20 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager \
  --max-num-seqs 64 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_xml \
  --reasoning-parser qwen3
```
> Set the smaller model's `--tool-call-parser` to match ITS format (a non-Qwen
> model may need `hermes`, `mistral`, `llama3_json`, etc.).

Total reserved: 0.45 + 0.20 = 0.65 → leaves ~50 GB free for a third model or
to bump either one up later.

### Adding a bigger model later

A bigger model (weights X GB) needs `gpu-memory-utilization ≥ (X + desired KV)
/ 143`. If the sum would exceed 0.95, lower the other models' fractions or shut
one down first. Watch live with:
```bash
nvidia-smi --query-gpu=memory.used,memory.total --format=csv -l 2
```
