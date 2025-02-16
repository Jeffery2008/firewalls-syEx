import os
import time
import shutil
import subprocess

def run_concrete_test(values, output_dir):
    """Run the C program with concrete values and return the result."""
    logs_dir = os.path.join(output_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    test_file = os.path.join(logs_dir, f"concrete_test_{int(time.time())}.c")
    output_c = os.path.join(output_dir, "output.c")
    
    with open(test_file, 'w') as f:
        f.write('''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

// Function prototypes
void init_rules(void);
int check_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, int proto);

// Include the implementation
#define CONCRETE_TEST
#include "../output.c"

int main() {
    uint32_t src_ip = %d;
    uint32_t dst_ip = %d;
    uint16_t src_port = %d;
    uint16_t dst_port = %d;
    int proto = %d;
    
    // Initialize rules
    init_rules();
    int result = check_packet(src_ip, dst_ip, src_port, dst_port, proto);
    printf("%%d\\n", result);  // Ensure clean output format
    return 0;
}
''' % (values['src_ip'], values['dst_ip'], 
       values['src_port'], values['dst_port'], values['proto']))

    try:
        executable = test_file + '.exe'
        subprocess.check_call(['gcc', test_file, '-o', executable])
        output = subprocess.check_output([executable]).decode('utf-8').strip()
        if not output:
            raise ValueError("No output from concrete test")
        return int(output)
    except (ValueError, subprocess.CalledProcessError) as e:
        print(f"Error running concrete test: {str(e)}")
        return None
    finally:
        if os.path.exists(executable):
            os.unlink(executable)

def parse_smt2_files(klee_output_dir, output_dir):
    """Parse and return the SMT2 formulas generated by KLEE."""
    smt_formulas = []
    
    for file in os.listdir(klee_output_dir):
        if file.endswith('.smt2'):
            test_num = file.split('test')[1].split('.')[0]
            ktest_file = os.path.join(klee_output_dir, f"test{test_num}.ktest")
            
            with open(os.path.join(klee_output_dir, file), 'r') as f:
                content = f.read()
            
            try:
                ktest_output = subprocess.check_output(['ktest-tool', ktest_file], 
                                                   stderr=subprocess.PIPE).decode('utf-8')
                
                concrete_values = {}
                current_name = None
                
                for line in ktest_output.splitlines():
                    if 'name:' in line:
                        current_name = line.split('name: \'')[1].split('\'')[0]
                    elif current_name and 'int :' in line:
                        value = int(line.split('int : ')[1])
                        concrete_values[current_name] = value
                        current_name = None

                print(f"\n\nCurrent directory:\n\n {os.getcwd()}\n\n")
                test_result = run_concrete_test(concrete_values, output_dir)
                path_type = "ACCEPT" if test_result == 1 else "DROP"
                smt_formulas.append((path_type, content))
                
            except (subprocess.CalledProcessError, IOError) as e:
                print(f"Warning: Could not process {ktest_file}: {str(e)}")
                continue
    
    return smt_formulas

def run_klee(c_filename):
    """Compile the generated C file to LLVM bitcode and run KLEE."""
    output_dir = os.path.dirname(c_filename)
    bc_filename = c_filename.replace(".c", ".bc")
    try:
        if os.path.exists("klee-out-0"):
            shutil.rmtree("klee-out-0")
            
        subprocess.check_call(["clang", "-DUSE_KLEE", "-I/usr/local/include/klee", "-emit-llvm", "-c", c_filename, "-o", bc_filename])
        result = subprocess.check_output(["klee", "--write-smt2s", bc_filename], 
                                      stderr=subprocess.STDOUT).decode("utf-8")
       
        print(f"KLEE output: {result}")
        klee_output_dir = os.path.join(os.path.dirname(c_filename), "klee-out-0")
        smt_formulas = parse_smt2_files(klee_output_dir, output_dir)
        return result, smt_formulas
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"KLEE failed: {e.output.decode('utf-8')}")