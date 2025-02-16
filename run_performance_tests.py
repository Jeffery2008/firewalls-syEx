#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
from pathlib import Path
import datetime
import shutil

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.append(str(PROJECT_ROOT))

# Results directory
RESULTS_DIR = PROJECT_ROOT / "test_results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_performance_tests(args):
    """Run the performance tests."""
    print("🚀 Running performance tests...")
    
    result = subprocess.run(
        ["pytest", "tests/test_performance_firewalls.py", "-v", "-m", "performance"],
        capture_output=True,
        text=True
    )
    
    # Save output
    with open(RESULTS_DIR / "performance_test_output.txt", "w") as f:
        f.write(result.stdout)
        if result.stderr:
            f.write("\n\nERRORS/WARNINGS:\n")
            f.write(result.stderr)
    
    if result.returncode != 0:
        print("❌ Performance tests failed!")
        print(result.stderr)
        if not args.force_continue:
            sys.exit(1)
        print("Continuing despite failures (--force-continue enabled)")
    else:
        print("✅ Performance tests completed successfully")
    
    return result.returncode == 0

def generate_visualizations(args):
    """Generate performance visualizations."""
    print("📊 Generating visualizations...")
    
    result = subprocess.run(
        ["pytest", "tests/test_performance_visualization.py", "-v", "-m", "visualization"],
        capture_output=True,
        text=True
    )
    
    # Save output
    with open(RESULTS_DIR / "visualization_output.txt", "w") as f:
        f.write(result.stdout)
        if result.stderr:
            f.write("\n\nERRORS/WARNINGS:\n")
            f.write(result.stderr)
    
    if result.returncode != 0:
        print("❌ Visualization generation failed!")
        print(result.stderr)
        if not args.force_continue:
            sys.exit(1)
        print("Continuing despite failures (--force-continue enabled)")
    else:
        print("✅ Visualizations generated successfully")
    
    return result.returncode == 0

def create_archive(timestamp):
    """Create an archive of the test results."""
    archive_name = f"performance_results_{timestamp}"
    shutil.make_archive(
        base_name=RESULTS_DIR / archive_name,
        format='zip',
        root_dir=RESULTS_DIR,
        base_dir='.'
    )
    print(f"📦 Results archived to {RESULTS_DIR}/{archive_name}.zip")

def main():
    parser = argparse.ArgumentParser(description="Run firewall performance tests and generate visualizations")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running performance tests")
    parser.add_argument("--skip-viz", action="store_true", help="Skip generating visualizations")
    parser.add_argument("--force-continue", action="store_true", help="Continue even if tests fail")
    parser.add_argument("--archive", action="store_true", help="Create archive of results")
    args = parser.parse_args()
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"🔍 Starting performance analysis at {timestamp}")
    print(f"📁 Results will be saved to {RESULTS_DIR}")
    
    # Run tests if not skipped
    tests_ok = True
    if not args.skip_tests:
        tests_ok = run_performance_tests(args)
    else:
        print("⏩ Skipping performance tests")
    
    # Generate visualizations if not skipped
    viz_ok = True
    if not args.skip_viz:
        if not tests_ok and not args.force_continue:
            print("⚠️ Skipping visualization due to test failures")
        else:
            viz_ok = generate_visualizations(args)
    else:
        print("⏩ Skipping visualizations")
    
    # Summary
    print("\n📋 Summary:")
    print(f"- Tests: {'✅ Passed' if tests_ok else '❌ Failed'}")
    print(f"- Visualizations: {'✅ Generated' if viz_ok else '❌ Failed'}")
    
    # Create archive if requested
    if args.archive:
        create_archive(timestamp)
    
    if not (tests_ok and viz_ok) and not args.force_continue:
        sys.exit(1)

if __name__ == "__main__":
    main()
