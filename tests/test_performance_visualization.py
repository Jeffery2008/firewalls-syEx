import os
import sys
import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pytest
import pandas as pd

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

# Test data directory
TEST_DATA_DIR = PROJECT_ROOT / "tests" / "test_data"
RESULTS_DIR = PROJECT_ROOT / "test_results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def read_performance_data(filename: str) -> pd.DataFrame:
    """Read performance data from a file and return as DataFrame."""
    data = []
    with open(TEST_DATA_DIR / filename, 'r') as f:
        for line in f:
            if line.strip():
                parts = line.strip().split(',')
                entry = {}
                for part in parts:
                    key, value = part.strip().split(':')
                    if 'Rules' in key:
                        entry['rules'] = int(value)
                    elif 'time' in key.lower() or 'duration' in key.lower():
                        entry[key.strip().lower()] = float(value.replace('s', ''))
                data.append(entry)
    return pd.DataFrame(data)

def plot_scaling_performance(save=True):
    """Create scaling performance visualization."""
    df = read_performance_data('scaling_results.txt')
    
    plt.figure(figsize=(10, 6))
    plt.plot(df['rules'], df['avg_time'], 'b-', label='Average Time')
    plt.fill_between(df['rules'], df['min_time'], df['max_time'], 
                     alpha=0.2, color='blue', label='Min-Max Range')
    
    plt.xlabel('Number of Rules')
    plt.ylabel('Translation Time (seconds)')
    plt.title('Translation Time Scaling')
    plt.legend()
    plt.grid(True)
    
    if save:
        plt.savefig(RESULTS_DIR / 'scaling_performance.png')
        plt.close()
    else:
        plt.show()

def plot_concurrent_performance(save=True):
    """Create concurrent execution visualization."""
    df = read_performance_data('concurrent_results.txt')
    
    plt.figure(figsize=(10, 6))
    plt.bar(range(len(df)), df['duration'], alpha=0.8)
    plt.xticks(range(len(df)), df['rules'])
    
    plt.xlabel('Number of Rules')
    plt.ylabel('Execution Time (seconds)')
    plt.title('Concurrent Translation Performance')
    plt.grid(True, axis='y')
    
    if save:
        plt.savefig(RESULTS_DIR / 'concurrent_performance.png')
        plt.close()
    else:
        plt.show()

def plot_verification_overhead(save=True):
    """Create verification overhead visualization."""
    with open(TEST_DATA_DIR / 'verification_performance.txt', 'r') as f:
        lines = f.readlines()
        times = {}
        for line in lines:
            key, value = line.strip().split(':')
            times[key.strip()] = float(value.replace('s', ''))
    
    plt.figure(figsize=(8, 6))
    bars = plt.bar(['Without Verification', 'With Verification'], 
                   [times['Time without verification'], times['Time with verification']])
    
    # Add overhead percentage label
    overhead_pct = ((times['Time with verification'] - times['Time without verification']) / 
                    times['Time without verification'] * 100)
    plt.text(bars[1].get_x() + bars[1].get_width()/2, bars[1].get_height(),
             f'+{overhead_pct:.1f}%',
             ha='center', va='bottom')
    
    plt.ylabel('Time (seconds)')
    plt.title('Translation Time with and without Verification')
    plt.grid(True, axis='y')
    
    if save:
        plt.savefig(RESULTS_DIR / 'verification_overhead.png')
        plt.close()
    else:
        plt.show()

def plot_smt_generation_performance(save=True):
    """Create SMT formula generation performance visualization."""
    df = read_performance_data('smt_generation_results.txt')
    
    plt.figure(figsize=(10, 6))
    plt.plot(df['rules'], df['avg_time'], 'r-', label='Average Time')
    plt.fill_between(df['rules'], df['min_time'], df['max_time'],
                     alpha=0.2, color='red', label='Min-Max Range')
    
    # Add trendline
    z = np.polyfit(df['rules'], df['avg_time'], 2)
    p = np.poly1d(z)
    x_trend = np.linspace(df['rules'].min(), df['rules'].max(), 100)
    plt.plot(x_trend, p(x_trend), '--', color='gray', label='Trend (Quadratic)')
    
    plt.xlabel('Number of Rules')
    plt.ylabel('Generation Time (seconds)')
    plt.title('SMT Formula Generation Performance')
    plt.legend()
    plt.grid(True)
    
    if save:
        plt.savefig(RESULTS_DIR / 'smt_generation_performance.png')
        plt.close()
    else:
        plt.show()

@pytest.mark.visualization
def test_create_performance_visualizations():
    """Generate all performance visualizations."""
    # Create visualizations
    plot_scaling_performance()
    plot_concurrent_performance()
    plot_verification_overhead()
    plot_smt_generation_performance()
    
    # Verify files were created
    assert (RESULTS_DIR / 'scaling_performance.png').exists()
    assert (RESULTS_DIR / 'concurrent_performance.png').exists()
    assert (RESULTS_DIR / 'verification_overhead.png').exists()
    assert (RESULTS_DIR / 'smt_generation_performance.png').exists()

def create_performance_report():
    """Generate a comprehensive performance report."""
    report = ["# Firewall Translation Performance Report\n"]
    
    # Add scaling analysis
    df_scaling = read_performance_data('scaling_results.txt')
    report.append("## Translation Scaling Analysis")
    report.append("Average translation time per rule:")
    report.append(f"- 10 rules: {df_scaling.iloc[0]['avg_time']/10:.3f}s per rule")
    report.append(f"- 1000 rules: {df_scaling.iloc[-1]['avg_time']/1000:.3f}s per rule")
    report.append(f"Scaling factor: {(df_scaling.iloc[-1]['avg_time']/1000)/(df_scaling.iloc[0]['avg_time']/10):.2f}x\n")
    
    # Add verification analysis
    with open(TEST_DATA_DIR / 'verification_performance.txt', 'r') as f:
        lines = f.readlines()
        times = {}
        for line in lines:
            key, value = line.strip().split(':')
            times[key.strip()] = float(value.replace('s', ''))
    
    report.append("## Verification Performance")
    report.append(f"Translation time without verification: {times['Time without verification']:.3f}s")
    report.append(f"Translation time with verification: {times['Time with verification']:.3f}s")
    overhead_pct = ((times['Time with verification'] - times['Time without verification']) / 
                    times['Time without verification'] * 100)
    report.append(f"Verification overhead: {overhead_pct:.1f}%\n")
    
    # Add concurrent execution analysis
    df_concurrent = read_performance_data('concurrent_results.txt')
    report.append("## Concurrent Execution Performance")
    report.append("Average execution times:")
    for _, row in df_concurrent.iterrows():
        report.append(f"- {row['rules']} rules: {row['duration']:.3f}s")
    report.append("")
    
    # Add SMT generation analysis
    df_smt = read_performance_data('smt_generation_results.txt')
    report.append("## SMT Formula Generation Performance")
    report.append("Average generation time per rule:")
    report.append(f"- 10 rules: {df_smt.iloc[0]['avg_time']/10:.3f}s per rule")
    report.append(f"- 500 rules: {df_smt.iloc[-1]['avg_time']/500:.3f}s per rule")
    report.append(f"Scaling factor: {(df_smt.iloc[-1]['avg_time']/500)/(df_smt.iloc[0]['avg_time']/10):.2f}x\n")
    
    # Write report
    with open(RESULTS_DIR / 'performance_report.md', 'w') as f:
        f.write('\n'.join(report))

@pytest.mark.visualization
def test_create_performance_report():
    """Generate the performance report."""
    create_performance_report()
    assert (RESULTS_DIR / 'performance_report.md').exists()

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'visualization'])
