#!/usr/bin/env python3
"""
Plotting script for LLM Database Security Evaluation
Creates visualizations for the experimental results
"""

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from matplotlib.ticker import MultipleLocator
import os

# Set style for better looking plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

def create_comprehensive_plots():
    """
    Create comprehensive visualization plots for the security evaluation
    """
    # Create output directory
    os.makedirs('analysis/plots', exist_ok=True)
    
    # Sample data (since we don't have real experiment data yet)
    data = {
        'Configuration': ['D0', 'DA', 'DB', 'DC-a', 'DC-b', 'DC-c', 'D++', 'I6'],
        'ASR': [0.95, 0.75, 0.65, 0.20, 0.05, 0.02, 0.01, 0.00],
        'Latency': [1.2, 1.4, 1.8, 1.25, 1.3, 1.35, 1.4, 1.45],
        'Energy': [0.05, 0.06, 0.08, 0.055, 0.06, 0.065, 0.07, 0.075]
    }
    
    df = pd.DataFrame(data)
    
    # Create figure with subplots
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle('LLM Database Security Evaluation: Comprehensive Analysis', fontsize=16, fontweight='bold')
    
    # Plot 1: ASR by Configuration - Bar Chart
    bars1 = ax1.bar(df['Configuration'], df['ASR'], color='skyblue', edgecolor='navy', linewidth=0.5)
    ax1.set_xlabel('Configuration')
    ax1.set_ylabel('Attack Success Rate (ASR)')
    ax1.set_title('ASR by Configuration')
    ax1.set_ylim(0, 1)
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                f'{height:.2f}',
                ha='center', va='bottom', fontsize=8)
    
    # Plot 2: Trade-off - ASR vs Latency
    scatter = ax2.scatter(df['Latency'], df['ASR'], s=100, c='coral', alpha=0.7)
    ax2.set_xlabel('Latency (seconds)')
    ax2.set_ylabel('Attack Success Rate (ASR)')
    ax2.set_title('ASR vs Latency Trade-off')
    ax2.grid(alpha=0.3)
    
    # Add configuration labels
    for i, config in enumerate(df['Configuration']):
        ax2.annotate(config, (df['Latency'][i], df['ASR'][i]), 
                    xytext=(5, 5), textcoords='offset points', fontsize=6)
    
    # Plot 3: Trade-off - ASR vs Energy
    scatter = ax3.scatter(df['Energy'], df['ASR'], s=100, c='lightgreen', alpha=0.7)
    ax3.set_xlabel('Energy Consumption (Wh)')
    ax3.set_ylabel('Attack Success Rate (ASR)')
    ax3.set_title('ASR vs Energy Trade-off')
    ax3.grid(alpha=0.3)
    
    # Add configuration labels
    for i, config in enumerate(df['Configuration']):
        ax3.annotate(config, (df['Energy'][i], df['ASR'][i]), 
                    xytext=(5, 5), textcoords='offset points', fontsize=6)
    
    # Plot 4: Multi-metric comparison
    x = np.arange(len(df['Configuration']))
    width = 0.25
    
    ax4.bar(x - width, df['ASR'], width, label='ASR', alpha=0.7)
    ax4.bar(x, df['Latency'], width, label='Latency', alpha=0.7)
    ax4.bar(x + width, df['Energy'], width, label='Energy', alpha=0.7)
    
    ax4.set_xlabel('Configuration')
    ax4.set_ylabel('Normalized Value')
    ax4.set_title('Multi-metric Comparison')
    ax4.set_xticks(x)
    ax4.set_xticklabels(df['Configuration'], rotation=45, ha='right')
    ax4.legend()
    ax4.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('analysis/plots/comprehensive_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("Comprehensive analysis plot saved to analysis/plots/comprehensive_analysis.png")
    
    # Create individual plots for each target
    targets = ['G-R1', 'G-R2', 'G-W1', 'G-W2', 'G-W3', 'G-S1']
    
    # Create a heatmap-like visualization for all targets
    fig, ax = plt.subplots(figsize=(12, 8))
    
    # Create matrix with configurations as rows and targets as columns
    asr_matrix = []
    for config in df['Configuration']:
        row = []
        for target in targets:
            # For sample data, we'll assign reasonable values
            if target.startswith('G-R'):
                if config in ['D0', 'DA']:
                    row.append(0.90)  # High ASR for baseline configurations
                elif config in ['DB']:
                    row.append(0.65)  # Moderate ASR for DB guardrail
                elif config in ['DC-a', 'DC-b', 'DC-c']:
                    row.append(0.05)  # Low ASR for security layers
                else:  # I6 and D++
                    row.append(0.00)  # Lowest ASR
            elif target.startswith('G-W'):
                if config in ['D0', 'DA']:
                    row.append(0.75)  # High ASR for baseline configurations  
                elif config in ['DB']:
                    row.append(0.50)  # Moderate ASR for DB guardrail
                elif config in ['DC-a', 'DC-b', 'DC-c']:
                    row.append(0.05)  # Low ASR for security layers
                else:  # I6 and D++
                    row.append(0.00)  # Lowest ASR
            else:  # G-S1
                if config in ['D0', 'DA']:
                    row.append(0.85)  # High ASR for baseline configurations
                elif config in ['DB']:
                    row.append(0.60)  # Moderate ASR for DB guardrail
                elif config in ['DC-a', 'DC-b', 'DC-c']:
                    row.append(0.10)  # Low ASR for security layers
                else:  # I6 and D++
                    row.append(0.01)  # Lowest ASR
            
        asr_matrix.append(row)
    
    # Create heatmap
    im = ax.imshow(asr_matrix, cmap='RdYlGn_r', aspect='auto')
    
    # Labels
    ax.set_xticks(range(len(targets)))
    ax.set_xticklabels(targets, rotation=45, ha='right')
    ax.set_yticks(range(len(df['Configuration'])))
    ax.set_yticklabels(df['Configuration'])
    
    # Add text annotations
    for i in range(len(df['Configuration'])):
        for j in range(len(targets)):
            text = ax.text(j, i, f'{asr_matrix[i][j]:.2f}',
                          ha="center", va="center", color="black", fontsize=8)
    
    ax.set_title("ASR by Configuration and Target")
    plt.colorbar(im, ax=ax, label='Attack Success Rate')
    
    plt.tight_layout()
    plt.savefig('analysis/plots/asr_heatmap.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("Heatmap plot saved to analysis/plots/asr_heatmap.png")
    
    # Create stacked bar chart for security layers
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Data for security layers
    security_layers = ['DC-a', 'DC-b', 'DC-c', 'D++', 'I6']
    asr_values = [0.20, 0.05, 0.02, 0.01, 0.00]
    latency_values = [1.25, 1.3, 1.35, 1.4, 1.45]
    energy_values = [0.055, 0.06, 0.065, 0.07, 0.075]
    
    x = np.arange(len(security_layers))
    width = 0.25
    
    ax.bar(x - width, asr_values, width, label='ASR', alpha=0.7)
    ax.set_xlabel('Security Layer')
    ax.set_ylabel('Value')
    ax.set_title('Security Layer Performance Metrics')
    ax.set_xticks(x)
    ax.set_xticklabels(security_layers, rotation=45, ha='right')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # Add value labels
    for i, (asr, lat, en) in enumerate(zip(asr_values, latency_values, energy_values)):
        ax.text(i - width, asr + 0.005, f'{asr:.3f}', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig('analysis/plots/security_layers_comparison.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("Security layers comparison plot saved to analysis/plots/security_layers_comparison.png")

def main():
    print("Creating comprehensive plots for LLM Database Security Analysis...")
    create_comprehensive_plots()
    print("All plots have been generated successfully!")

if __name__ == "__main__":
    main()