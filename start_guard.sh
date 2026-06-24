#!/usr/bin/env bash
# =============================================================================
# start_guard.sh  —  serve Llama Guard 3-8B via vLLM on port 8003
# -----------------------------------------------------------------------------
# This is the Defense-B LLM guard model. Run in a tmux pane.
#
# GPU budget (all FP8, H200 141 GB):
#   victim   (Qwen3.6-27B-FP8)  port 8001  util 0.28  ~39 GB budget
#   attacker (Hermes-4-70B-FP8) port 8002  util 0.62  ~87 GB budget
#   guard    (LlamaGuard-3-8B)  port 8003  util 0.07  ~10 GB budget
#   total headroom                                     ~5 GB remaining
#
# Usage:
#   tmux new-session -d -s guard 'bash start_guard.sh'
# =============================================================================

source ~/LLM/vllm_env/bin/activate

export CUDA_HOME=/usr/local/cuda
export PATH=$CUDA_HOME/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:${LD_LIBRARY_PATH:-}
export MAX_JOBS=4
export NVCC_THREADS=1
export VLLM_DEEP_GEMM_WARMUP=skip

python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-Guard-3-8B \
  --served-model-name llama-guard-3-8b \
  --host 127.0.0.1 \
  --port 8003 \
  --quantization fp8 \
  --gpu-memory-utilization 0.10 \
  --max-model-len 4096 \
