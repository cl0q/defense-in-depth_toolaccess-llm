#!/bin/bash
# Garak Baseline Script für die Bachelorarbeit
# Misst bekannte Jailbreaks/Injections gegen das nackte Modell

# Set working directory
cd /home/secai2/defense-in-depth_toolaccess-llm

# Run garak with baseline tests
# Test against the raw LLM without any defenses
garak --model_type huggingface --model_name_or_path Qwen/Qwen3-14B --probes llm-jailbreak --output_dir ./garak_results --config ./garak_config.yaml

echo "Garak Baseline Tests abgeschlossen"