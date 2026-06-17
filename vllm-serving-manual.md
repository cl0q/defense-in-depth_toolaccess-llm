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
  --max-model-len 32768 \
  --gpu-memory-utilization 0.90 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager \
  --max-num-seqs 64
```

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

## Running multiple models at once (later goal)

Good news: on this box **VRAM (143 GB) is plentiful, host RAM (64 GB) is the
bottleneck.** You never load two models into RAM simultaneously — the streamer
stages each one through its small bounded buffer, then frees it. So:

- Give each model its own **`--port`** and a slice of VRAM via
  **`--gpu-memory-utilization`** (e.g. 0.45 + 0.45 for two models, leaving
  headroom).
- Launch each in its **own tmux session**.
- Keep `MAX_JOBS=4` global — if you start two at once they share the CPU, so
  consider launching them **sequentially** (let the first finish compiling
  before starting the second) to avoid stacking compile RAM.

Example second (smaller) model:
```bash
vllm serve <small-model> \
  --host 0.0.0.0 --port 8001 \
  --gpu-memory-utilization 0.30 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
  --enforce-eager
```
