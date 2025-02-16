import os
import sys
import time
import pytest
import statistics
from pathlib import Path
from typing import List, Tuple

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from firewalls_app import FirewallManager

# Test data directory
TEST_DATA_DIR = PROJECT_ROOT / "tests" / "test_data"
TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

def generate_rules(num_rules: int) -> str:
    """Generate a specified number of iptables rules."""
    rules = []
    for i in range(num_rules):
        port = 1024 + (i % 64000)  # Use different ports
        rules.append(f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
    return "\n".join(rules)

@pytest.fixture
def large_ruleset():
    """Create a large ruleset with 1000 rules."""
    rules = generate_rules(1000)
    rules_file = TEST_DATA_DIR / "large_ruleset.txt"
    rules_file.write_text(rules)
    return str(rules_file)

def measure_execution_time(func, *args) -> Tuple[float, float, float]:
    """Measure execution time statistics over multiple runs."""
    times = []
    for _ in range(5):  # Run 5 times for statistical significance
        start_time = time.perf_counter()
        func(*args)
        end_time = time.perf_counter()
        times.append(end_time - start_time)
    
    return (
        min(times),  # Best case
        statistics.mean(times),  # Average case
        max(times)  # Worst case
    )

@pytest.mark.performance
def test_translation_scaling():
    """Test how translation time scales with ruleset size."""
    manager = FirewallManager()
    sizes = [10, 50, 100, 500, 1000]
    results = []
    
    for size in sizes:
        rules = generate_rules(size)
        rules_file = TEST_DATA_DIR / f"rules_{size}.txt"
        rules_file.write_text(rules)
        
        def translate():
            return manager.process_rules(str(rules_file), skip_verify=True)
        
        min_time, avg_time, max_time = measure_execution_time(translate)
        results.append({
            'size': size,
            'min_time': min_time,
            'avg_time': avg_time,
            'max_time': max_time
        })
        
        # Performance assertions
        assert avg_time < size * 0.1, f"Translation too slow for {size} rules"
    
    # Log results for analysis
    with open(TEST_DATA_DIR / "scaling_results.txt", 'w') as f:
        for result in results:
            f.write(f"Rules: {result['size']}, "
                   f"Min: {result['min_time']:.3f}s, "
                   f"Avg: {result['avg_time']:.3f}s, "
                   f"Max: {result['max_time']:.3f}s\n")

@pytest.mark.performance
def test_memory_usage(large_ruleset):
    """Test memory usage during translation."""
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    manager = FirewallManager()
    manager.process_rules(large_ruleset, skip_verify=True)
    
    final_memory = process.memory_info().rss / 1024 / 1024  # MB
    memory_increase = final_memory - initial_memory
    
    # Assert reasonable memory usage (less than 500MB increase)
    assert memory_increase < 500, f"Memory usage too high: {memory_increase:.2f}MB"

@pytest.mark.performance
def test_concurrent_translations():
    """Test performance under concurrent translations."""
    import concurrent.futures
    
    def translate_rules(size: int) -> Tuple[int, float]:
        rules = generate_rules(size)
        rules_file = TEST_DATA_DIR / f"concurrent_rules_{size}.txt"
        rules_file.write_text(rules)
        
        manager = FirewallManager()
        start_time = time.perf_counter()
        success, _ = manager.process_rules(str(rules_file), skip_verify=True)
        end_time = time.perf_counter()
        
        assert success, f"Translation failed for {size} rules"
        return size, end_time - start_time
    
    sizes = [10, 50, 100, 200, 500]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(translate_rules, size) for size in sizes]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    
    # Log concurrent execution results
    with open(TEST_DATA_DIR / "concurrent_results.txt", 'w') as f:
        for size, duration in sorted(results):
            f.write(f"Rules: {size}, Duration: {duration:.3f}s\n")

@pytest.mark.performance
def test_verification_performance(large_ruleset):
    """Test performance of rule verification."""
    manager = FirewallManager()
    
    def translate_with_verify():
        return manager.process_rules(large_ruleset)
    
    def translate_without_verify():
        return manager.process_rules(large_ruleset, skip_verify=True)
    
    # Measure times with and without verification
    _, avg_with_verify, _ = measure_execution_time(translate_with_verify)
    _, avg_without_verify, _ = measure_execution_time(translate_without_verify)
    
    verification_overhead = avg_with_verify - avg_without_verify
    
    # Log verification performance
    with open(TEST_DATA_DIR / "verification_performance.txt", 'w') as f:
        f.write(f"Time with verification: {avg_with_verify:.3f}s\n")
        f.write(f"Time without verification: {avg_without_verify:.3f}s\n")
        f.write(f"Verification overhead: {verification_overhead:.3f}s\n")
    
    # Assert reasonable verification overhead (less than 5x translation time)
    assert verification_overhead < avg_without_verify * 5, "Verification overhead too high"

@pytest.mark.performance
def test_smt_formula_generation_scaling():
    """Test how SMT formula generation time scales with ruleset size."""
    from iptablesToSMT.main import process_firewall
    
    sizes = [10, 50, 100, 500]
    results = []
    
    for size in sizes:
        rules = generate_rules(size)
        rules_file = TEST_DATA_DIR / f"smt_rules_{size}.txt"
        rules_file.write_text(rules)
        smt_file = TEST_DATA_DIR / f"smt_rules_{size}.smt2"
        
        def generate_smt():
            process_firewall(str(rules_file), str(smt_file))
        
        min_time, avg_time, max_time = measure_execution_time(generate_smt)
        results.append({
            'size': size,
            'min_time': min_time,
            'avg_time': avg_time,
            'max_time': max_time
        })
    
    # Log SMT generation results
    with open(TEST_DATA_DIR / "smt_generation_results.txt", 'w') as f:
        for result in results:
            f.write(f"Rules: {result['size']}, "
                   f"Min: {result['min_time']:.3f}s, "
                   f"Avg: {result['avg_time']:.3f}s, "
                   f"Max: {result['max_time']:.3f}s\n")

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'performance'])
