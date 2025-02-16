"""Validator for generated eBPF code to ensure security and correctness."""

import re
from pathlib import Path
from typing import List, Tuple, Dict, Any

def check_bounds_checking(code: str) -> List[Tuple[int, str]]:
    """Verify proper bounds checking is present for all packet access."""
    errors = []
    line_num = 1
    lines = code.split('\n')
    
    # Track header pointer declarations and their bounds checks
    header_ptrs = {
        'eth': False,
        'iph': False,
        'tcph': False,
        'udph': False,
        'icmph': False
    }
    
    for i, line in enumerate(lines):
        line_num = i + 1
        line = line.strip()
        
        # Check for header pointer declarations
        for ptr in header_ptrs.keys():
            if f"struct" in line and f"*{ptr}" in line:
                header_ptrs[ptr] = False  # Reset bounds check flag when ptr is declared
                
        # Look for bounds checking
        for ptr in header_ptrs.keys():
            if f"(void*)({ptr} + 1) > data_end" in line:
                header_ptrs[ptr] = True
                
        # Check for packet data access after pointer declaration
        for ptr in header_ptrs.keys():
            if f"{ptr}->" in line and not header_ptrs[ptr]:
                errors.append((line_num, f"Missing bounds check before accessing {ptr}"))
                
    return errors

def check_security_patterns(code: str) -> List[Tuple[int, str]]:
    """Check for common security patterns and potential issues."""
    errors = []
    line_num = 1
    
    # Required security patterns
    patterns = {
        'license': r'char\s+_license\[\]\s+SEC\("license"\)\s*=\s*"GPL"',
        'classifier': r'SEC\("classifier"\)',
        'sk_buff': r'struct\s+__sk_buff\s*\*skb',
    }
    
    for pattern_name, pattern in patterns.items():
        if not re.search(pattern, code):
            errors.append((0, f"Missing required {pattern_name} declaration"))
    
    # Check each line for potential issues
    lines = code.split('\n')
    for i, line in enumerate(lines):
        line_num = i + 1
        line = line.strip()
        
        # Check for potentially dangerous patterns
        if "inline" in line and not "__always_inline" in line:
            errors.append((line_num, "Use __always_inline instead of inline"))
            
        if "goto" in line:
            errors.append((line_num, "Avoid using goto statements in eBPF programs"))
            
        if "while" in line and not "for" in line:  # Allow for loops but warn about while
            errors.append((line_num, "While loops may be rejected by the verifier - consider using for"))

    return errors

def check_helper_functions(code: str) -> List[Tuple[int, str]]:
    """Verify proper use of BPF helper functions."""
    errors = []
    line_num = 1
    
    allowed_helpers = {
        'bpf_trace_printk',
        'bpf_skb_load_bytes',
        'bpf_skb_store_bytes',
        'bpf_l3_csum_replace',
        'bpf_l4_csum_replace',
        'bpf_tail_call',
        'bpf_clone_redirect',
        'bpf_redirect',
        'bpf_perf_event_output',
        'bpf_skb_event_output',
        'bpf_get_smp_processor_id',
        'bpf_get_prandom_u32',
        'bpf_get_numa_node_id',
        'bpf_ktime_get_ns',
        'bpf_skb_ct_state_get',
    }
    
    lines = code.split('\n')
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Check for bpf helper function calls
        if 'bpf_' in line:
            helper_match = re.search(r'bpf_\w+', line)
            if helper_match:
                helper = helper_match.group()
                if helper not in allowed_helpers:
                    errors.append((line_num, f"Using potentially unsupported helper function: {helper}"))
    
    return errors

def check_map_operations(code: str) -> List[Tuple[int, str]]:
    """Check for proper map declarations and operations."""
    errors = []
    line_num = 1
    
    lines = code.split('\n')
    for i, line in enumerate(lines):
        line_num = i + 1
        line = line.strip()
        
        # Check map declarations
        if "SEC(\"maps\")" in line:
            if not re.search(r'struct\s+bpf_map_def\s+SEC\("maps"\)', code):
                errors.append((line_num, "Map declaration missing struct bpf_map_def"))
                
        # Check map access helpers
        map_helpers = ['bpf_map_lookup_elem', 'bpf_map_update_elem', 'bpf_map_delete_elem']
        for helper in map_helpers:
            if helper in line:
                if not re.search(r'if\s*\(\s*[^=]=\s*NULL\s*\)', code):
                    errors.append((line_num, f"Missing NULL check after {helper}"))
    
    return errors

def check_performance_patterns(code: str) -> List[Tuple[int, str]]:
    """Identify potential performance bottlenecks and optimization opportunities."""
    warnings = []
    lines = code.split('\n')
    
    # Track loop and function state
    loop_depth = 0
    loop_lines = []
    current_function = None
    tail_call_opportunities = []
    packet_accesses = []
    
    # Track inefficient patterns
    nested_map_accesses = set()
    redundant_header_checks = set()
    
    for i, line in enumerate(lines):
        line_num = i + 1
        line = line.strip()
        
        # Track function boundaries
        if re.search(r'SEC\(".*"\)\s*\w+\s+\w+\(', line):
            current_function = line
            
        # Analyze loop structures
        if re.search(r'\b(for|while)\s*\(', line):
            loop_depth += 1
            loop_lines.append(line_num)
            
            if loop_depth > 1:
                warnings.append((line_num, 
                    "Nested loop detected - consider restructuring to avoid potential performance impact"))
        
        # Check loop exit
        if '}' in line and loop_depth > 0:
            if any(l in line for l in ['break', 'return']):
                loop_depth -= 1
                
        # Check for tail call optimization opportunities
        if current_function and 'return' in line:
            if not re.search(r'bpf_tail_call', '\n'.join(lines[max(0, i-3):i+1])):
                tail_call_opportunities.append((line_num,
                    "Consider using tail call for better performance at program exit"))
        
        # Track packet header access patterns
        header_access = re.search(r'(eth|ip|tcp|udp|icmp)h->', line)
        if header_access:
            packet_accesses.append((header_access.group(1), line_num))
            
            # Check for inefficient header access patterns
            for prev_header, prev_line in packet_accesses[-2::-1]:
                if prev_header == header_access.group(1):
                    key = (prev_line, line_num)
                    if key not in redundant_header_checks:
                        redundant_header_checks.add(key)
                        warnings.append((line_num,
                            f"Potentially redundant {prev_header} header access - consider caching values"))
        
        # Check for map access patterns
        if 'bpf_map_lookup_elem' in line:
            # Track nested map lookups
            if loop_depth > 0:
                nested_map_accesses.add(line_num)
                warnings.append((line_num,
                    "Map lookup inside loop - consider caching lookup results"))
                    
            # Check for sequential map lookups
            for prev_line in range(max(0, i-3), i):
                if 'bpf_map_lookup_elem' in lines[prev_line]:
                    warnings.append((line_num,
                        "Multiple map lookups in close proximity - consider consolidating data structures"))
    
    # Add warnings for nested map accesses patterns
    if nested_map_accesses:
        affected_lines = ', '.join(str(x) for x in sorted(nested_map_accesses))
        warnings.append((0, f"Multiple map accesses in loops detected on lines: {affected_lines}"))
    
    return warnings

def validate_ebpf_code(code: str, log_file: str) -> bool:
    """
    Validate generated eBPF code for common issues and security concerns.
    
    Args:
        code: The eBPF C code to validate
        log_file: Path to write validation results
        
    Returns:
        bool: True if validation passes, False otherwise
    """
    all_errors = []
    
    # Run all validation checks
    all_errors.extend(check_bounds_checking(code))
    all_errors.extend(check_security_patterns(code))
    all_errors.extend(check_helper_functions(code))
    all_errors.extend(check_map_operations(code))
    
    # Run performance checks
    performance_warnings = check_performance_patterns(code)
    
    # Sort errors and warnings by line number
    all_errors.sort(key=lambda x: x[0])
    performance_warnings.sort(key=lambda x: x[0])
    
    # Write results to log
    with open(log_file, 'a') as f:
        f.write("\neBPF Code Validation Results:\n")
        
        if not all_errors and not performance_warnings:
            f.write("- All validation checks passed\n")
            return True
            
        if all_errors:
            f.write("- Validation errors found:\n")
            for line_num, error in all_errors:
                f.write(f"  * Line {line_num}: {error}\n")
        
        if performance_warnings:
            f.write("\n- Performance optimization opportunities:\n")
            for line_num, warning in performance_warnings:
                f.write(f"  * Line {line_num}: {warning}\n")
        
        return False

def format_error_report(issues: List[Tuple[int, str]], code: str, is_warning: bool = False) -> str:
    """
    Format validation issues with code context for better readability.
    
    Args:
        issues: List of (line_number, message) tuples
        code: The source code being analyzed
        is_warning: If True, format as warnings instead of errors
        
    Returns:
        str: Formatted report with code context
    """
    report = []
    lines = code.split('\n')
    
    for line_num, message in issues:
        if line_num > 0:  # Skip file-level issues
            # Get code context (1 line before and after)
            start = max(0, line_num - 2)
            end = min(len(lines), line_num + 1)
            
            issue_type = "Warning" if is_warning else "Error"
            report.append(f"\n{issue_type} on line {line_num}: {message}")
            report.append("Code context:")
            
            for i in range(start, end):
                prefix = "  > " if i == line_num - 1 else "    "
                report.append(f"{prefix}{i+1}: {lines[i]}")
                
    return '\n'.join(report)

if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate eBPF code for security and correctness")
    parser.add_argument("code_file", help="Path to the eBPF code file to validate")
    parser.add_argument("--log", "-l", help="Path to write validation log (default: <code_file>.validation.log)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed error messages with code context")
    
    args = parser.parse_args()
    
    # Set default log file if not specified
    if not args.log:
        args.log = str(Path(args.code_file).with_suffix('.validation.log'))
    
    try:
        with open(args.code_file, 'r') as f:
            code = f.read()
            
        result = validate_ebpf_code(code, args.log)
        
        if result:
            print(f"Validation passed - see {args.log} for details")
            sys.exit(0)
        else:
            print(f"Validation failed - see {args.log} for details")
            
            if args.verbose:
                # Get all errors and warnings again for formatting
                all_errors = []
                all_errors.extend(check_bounds_checking(code))
                all_errors.extend(check_security_patterns(code))
                all_errors.extend(check_helper_functions(code))
                all_errors.extend(check_map_operations(code))
                all_errors.sort(key=lambda x: x[0])
                
                performance_warnings = check_performance_patterns(code)
                performance_warnings.sort(key=lambda x: x[0])
                
                if all_errors:
                    print("\nDetailed error report:")
                    print(format_error_report(all_errors, code, is_warning=False))
                
                if performance_warnings:
                    print("\nDetailed performance warnings:")
                    print(format_error_report(performance_warnings, code, is_warning=True))
            
            sys.exit(1)
            
    except Exception as e:
        print(f"Error validating code: {str(e)}")
        sys.exit(1)
