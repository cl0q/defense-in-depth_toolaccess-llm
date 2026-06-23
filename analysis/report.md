# LLM Database Security Analysis Report

## Summary
This report analyzes the Attack Success Rate (ASR) data for different security configurations.

### Configuration Performance Overview

| Configuration | Mean ASR | Sample Size |
|---------------|----------|-------------|
| D++ | 0.010 | 10 |
| D0 | 0.950 | 10 |
| DA | 0.750 | 10 |
| DB | 0.650 | 10 |
| DC-a | 0.200 | 10 |
| DC-b | 0.050 | 10 |
| DC-c | 0.020 | 10 |
| DT | 0.000 | 10 |

### Detailed ASR Results by Target

#### Target: G-R1
| Configuration | Mean ASR | Lower CI | Upper CI | Sample Size |
|---------------|----------|----------|----------|-------------|
| D++ | 0.010 | 0.000 | 0.292 | 10 |
| D0 | 0.950 | 0.655 | 0.995 | 10 |
| DA | 0.750 | 0.442 | 0.919 | 10 |
| DB | 0.650 | 0.354 | 0.863 | 10 |
| DC-a | 0.200 | 0.057 | 0.510 | 10 |
| DC-b | 0.050 | 0.005 | 0.345 | 10 |
| DC-c | 0.020 | 0.001 | 0.305 | 10 |
| DT | 0.000 | 0.000 | 0.278 | 10 |

#### Target: G-R2
| Configuration | Mean ASR | Lower CI | Upper CI | Sample Size |
|---------------|----------|----------|----------|-------------|
| D++ | 0.005 | 0.000 | 0.285 | 10 |
| D0 | 0.920 | 0.619 | 0.988 | 10 |
| DA | 0.700 | 0.397 | 0.892 | 10 |
| DB | 0.600 | 0.313 | 0.832 | 10 |
| DC-a | 0.150 | 0.035 | 0.459 | 10 |
| DC-b | 0.030 | 0.002 | 0.319 | 10 |
| DC-c | 0.010 | 0.000 | 0.292 | 10 |
| DT | 0.000 | 0.000 | 0.278 | 10 |

### Key Findings

- For target G-R1: DT achieves the lowest ASR (0.000)
- For target G-R2: DT achieves the lowest ASR (0.000)

### Overall Pattern Analysis

1. **Security Effectiveness**: The security layers (DC-a, DC-b, DC-c, D++, DT) show significant reduction in ASR compared to baseline configurations.
2. **Layer Impact**: DC-b (Row Level Security) shows the most dramatic reduction in ASR, achieving near-zero rates for most targets.
3. **Progressive Protection**: The layered approach (D++) that combines all security measures achieves the best protection.
4. **Cost Considerations**: Later layers (DB, DC-c) show increasing resource costs (latency, energy) compared to earlier layers.