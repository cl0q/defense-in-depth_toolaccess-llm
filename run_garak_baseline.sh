#!/bin/bash
# Garak Baseline Script für die Bachelorarbeit
# Misst bekannte Jailbreaks/Injections gegen das nackte Modell

# Set working directory to script location
cd "$(dirname "$0")"

# Run garak with baseline tests
# Test against the raw LLM without any defenses
garak --config ./garak_config.yaml

echo "Garak Baseline Tests abgeschlossen"