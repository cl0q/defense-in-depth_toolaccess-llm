source /home/secai2/LLM/vllm_env/bin/activate

export CUDA_HOME=/usr/local/cuda
export PATH=$CUDA_HOME/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:${LD_LIBRARY_PATH:-}
export MAX_JOBS=4
export NVCC_THREADS=1
export VLLM_DEEP_GEMM_WARMUP=skip


vllm serve NousResearch/Hermes-4-70B-FP8 \
  --host 0.0.0.0 --port 8002 --served-model-name hermes-70b \
  --max-model-len 32768 --gpu-memory-utilization 0.59 \
  --load-format runai_streamer \
  --model-loader-extra-config '{"memory_limit": 4294967296}' \
