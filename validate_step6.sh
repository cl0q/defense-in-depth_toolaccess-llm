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
python3 -c "
import yaml
try:
    with open('redteam/promptfooconfig.yaml', 'r') as f:
        config = yaml.safe_load(f)
    print('   ✓ promptfooconfig.yaml is valid YAML')
    
    # Check required sections
    required_sections = ['targets', 'redteam']
    for section in required_sections:
        if section in config:
            print(f'   ✓ {section} section found')
        else:
            print(f'   ⚠ {section} section missing')
            
    # Check redteam subsections
    if 'redteam' in config:
        redteam = config['redteam']
        redteam_required = ['provider', 'plugins', 'strategies']
        for section in redteam_required:
            if section in redteam:
                print(f'   ✓ redteam.{section} found')
            else:
                print(f'   ⚠ redteam.{section} missing')
                
    # Check promptfoo keys for correct validation
    if 'redteam' in config and 'plugins' in config['redteam']:
        plugins = config['redteam']['plugins']
        expected_plugins = ['owasp:llm:01', 'owasp:llm:02', 'owasp:llm:05', 'owasp:llm:06']
        for plugin in expected_plugins:
            if plugin in plugins:
                print(f'   ✓ Plugin {plugin} found')
            else:
                print(f'   ⚠ Plugin {plugin} missing')
                
    if 'redteam' in config and 'strategies' in config['redteam']:
        strategies = config['redteam']['strategies']
        expected_strategies = ['jailbreak:meta', 'jailbreak:hydra', 'crescendo']
        for strategy in expected_strategies:
            if strategy in strategies:
                print(f'   ✓ Strategy {strategy} found')
            else:
                print(f'   ⚠ Strategy {strategy} missing')
                
except Exception as e:
    print(f'   ✗ promptfooconfig.yaml validation failed: {e}')
"

# Check attack files
echo "3. Checking attack files..."
for file in redteam/attacks/G-*.yaml; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo "   ✓ $filename"
        python3 -c "
import yaml
try:
    with open('$file', 'r') as f:
        attacks = yaml.safe_load(f)
    if isinstance(attacks, list) and len(attacks) > 0:
        print('   ✓ File contains valid attack list')
        for i, attack in enumerate(attacks):
            if 'description' in attack and 'prompt' in attack and 'expected_result' in attack:
                print(f'   ✓ Attack {i+1} has required fields')
                # Check for additional required fields
                if 'tags' in attack:
                    print(f'   ✓ Attack {i+1} has tags')
                else:
                    print(f'   ⚠ Attack {i+1} missing tags')
                if 'role' in attack:
                    print(f'   ✓ Attack {i+1} has role')
                else:
                    print(f'   ⚠ Attack {i+1} missing role')
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
echo "   Configurations: Layer-specific runs with --tag config=..."
echo "   Expected Promptfoo Keys: provider, plugins, strategies"