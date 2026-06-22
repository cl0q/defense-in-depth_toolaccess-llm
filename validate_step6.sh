#!/bin/bash
# Validation script for Step 6 implementation

echo "Validating Step 6 Implementation (Red-Teaming Configuration)"

# Check that all required files exist
echo "1. Checking required files..."
if [ -f "redteam/promptfooconfig.yaml" ]; then
    echo "   ✓ promptfooconfig.yaml exists"
else
    echo "   ✗ promptfooconfig.yaml missing"
fi

if [ -d "redteam/attacks" ]; then
    echo "   ✓ attacks directory exists"
    ATTACK_COUNT=$(ls redteam/attacks/*.yaml | wc -l)
    echo "   ✓ $ATTACK_COUNT attack files found"
else
    echo "   ✗ attacks directory missing"
fi

if [ -f "redteam/legit_set.yaml" ]; then
    echo "   ✓ legit_set.yaml exists"
else
    echo "   ✗ legit_set.yaml missing"
fi

# Validate YAML structure
echo "2. Validating YAML structure..."
python -c "
import yaml
try:
    with open('redteam/promptfooconfig.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print('   ✓ promptfooconfig.yaml is valid YAML')
    
    # Check required sections
    required_sections = ['targets', 'attackers', 'plugins', 'strategies', 'configs']
    for section in required_sections:
        if section in config:
            print(f'   ✓ {section} section found')
        else:
            print(f'   ⚠ {section} section missing')
            
except Exception as e:
    print(f'   ✗ promptfooconfig.yaml validation failed: {e}')
"

# Check attack files
echo "3. Checking attack files..."
for file in redteam/attacks/G-*.yaml; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo "   ✓ $filename"
        python -c "
import yaml
try:
    with open('$file', 'r') as f:
        attacks = yaml.safe_load(f)
    if isinstance(attacks, list) and len(attacks) > 0:
        print('   ✓ File contains valid attack list')
        for i, attack in enumerate(attacks):
            if 'description' in attack and 'prompt' in attack:
                print(f'   ✓ Attack {i+1} has required fields')
            else:
                print(f'   ⚠ Attack {i+1} missing required fields')
    else:
        print('   ⚠ File does not contain valid attack list')
except Exception as e:
    print(f'   ✗ $filename validation failed: {e}')
"
    fi
done

echo "4. Configuration Overview:"
echo "   Target: HTTP endpoint (Gateway)"
echo "   Attacker: HTTP endpoint (vLLM)"
echo "   Plugins: OWASP LLM vulnerabilities"
echo "   Strategies: Crescendo, Hydra, Meta"
echo "   Configurations: All defense layers (D0-I6)"
echo "   Attack Types: All success goals (G-R1-G-S1)"