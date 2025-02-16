import subprocess
import shutil
import platform
from pathlib import Path
import os

def is_wsl():
    """Check if running under Windows Subsystem for Linux."""
    if os.path.exists('/proc/version'):
        with open('/proc/version', 'r') as f:
            if "microsoft" in f.read().lower():
                return True
    return False

def get_system_header_paths():
    """Get system-specific eBPF header paths."""
    if platform.system() == "Linux" or is_wsl():
        paths = [
            "/usr/include/linux",
            "/usr/include/x86_64-linux-gnu",
            "/usr/local/include",
        ]
        # Add kernel headers path if available
        kernel_release = subprocess.check_output(['uname', '-r']).decode().strip()
        kernel_headers = f"/usr/src/linux-headers-{kernel_release}/include"
        if Path(kernel_headers).exists():
            paths.append(kernel_headers)
        return paths
    elif platform.system() == "Darwin":  # macOS
        return [
            "/usr/local/include",
            "/opt/homebrew/include",
        ]
    else:  # Windows (non-WSL)
        return []

def find_wsl_clang():
    """Use clang installed in WSL."""
    try:
        subprocess.run(["wsl", "which", "clang"], check=True, capture_output=True)
        return "clang"
    except subprocess.CalledProcessError:
        raise FileNotFoundError(
            "Could not find clang in WSL.\n"
            "Please ensure you have installed clang in your WSL environment:\n"
            "wsl sudo apt install clang llvm"
        )

def wsl_path(windows_path):
    """Convert Windows path to WSL path."""
    # Convert absolute Windows path to WSL path
    if isinstance(windows_path, Path):
        windows_path = str(windows_path)
    drive = windows_path[0].lower()
    wsl_path = windows_path.replace('\\', '/').replace(':', '')
    return f"/mnt/{drive}/{wsl_path}"

def check_wsl_headers():
    """Check if required eBPF headers are available in WSL."""
    header_check_cmd = [
        "wsl", "bash", "-c",
        "ls /usr/include/linux/{bpf,pkt_cls,if_ether,ip,tcp}.h 2>/dev/null"
    ]
    
    result = subprocess.run(header_check_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise FileNotFoundError(
            "Missing required eBPF headers in WSL.\n"
            "Please install the Linux headers package:\n"
            "wsl sudo apt-get install linux-headers-generic"
        )
    
    # Return the found header paths (for logging purposes)
    return result.stdout.strip().split('\n')

def run_wsl_command(cmd, check=True, **kwargs):
    """Run a command in WSL with proper encoding handling."""
    result = subprocess.run(
        ["wsl", "bash", "-c", cmd],
        encoding='utf-8',
        errors='replace',
        **kwargs
    )
    if check and result.returncode != 0:
        error_msg = f"WSL command failed with exit code {result.returncode}\n"
        if result.stdout:
            error_msg += f"stdout:\n{result.stdout}\n"
        if result.stderr:
            error_msg += f"stderr:\n{result.stderr}"
        raise subprocess.CalledProcessError(
            result.returncode,
            cmd,
            output=result.stdout,
            stderr=result.stderr
        )
    return result

def generate_smt_from_ebpf(ebpf_code, include_paths=None):
    """Generate SMT formula from eBPF code using WSL."""
    # Setup directories
    output_dir = Path("eBPFToSMT")
    output_dir.mkdir(exist_ok=True)

    # Save eBPF code to file
    ebpf_file = output_dir / "ebpf.c"
    smt_file = output_dir / "ebpf.smt2"
    ebpf_file.write_text(ebpf_code)

    try:
        # Convert Windows paths to WSL paths
        wsl_out_dir = wsl_path(output_dir.absolute())
        wsl_ebpf_file = wsl_path(ebpf_file.absolute())
        
        # Find clang in WSL and check headers
        clang = find_wsl_clang()
        headers = check_wsl_headers()
        print("Found WSL headers:", headers)

        # Create output directory in WSL
        run_wsl_command(f'mkdir -p "{wsl_out_dir}"')

        # Install additional required headers
        run_wsl_command('sudo apt-get install -y libbpf-dev linux-headers-$(uname -r)', capture_output=True)

        # Compile with clang in WSL
        compile_cmd = (
            f'clang -v -target bpf -emit-llvm -c -g -O2 '
            f'-I/usr/include/linux '
            f'-I/usr/include '
            f'-I/usr/include/x86_64-linux-gnu '
            f'-I/usr/src/linux-headers-$(uname -r)/include '
            f'-I/usr/src/linux-headers-$(uname -r)/arch/x86/include '
            f'-I/usr/src/linux-headers-$(uname -r)/arch/x86/include/generated '
            f'-I/usr/include/bpf '
            f'"{wsl_ebpf_file}" -o "{wsl_out_dir}/ebpf.bc" 2>&1'
        )
        
        # Run eBPF to LLVM conversion
        print("Compiling eBPF to LLVM bitcode in WSL...")
        result = run_wsl_command(compile_cmd, capture_output=True)
        
        if result.stdout:
            print("Compiler output:")
            print(result.stdout)

        # Convert LLVM bitcode to SMT using Python in WSL
        print("Converting LLVM bitcode to SMT formula...")
        llvm2smt_cmd = (
            f'python3 "{wsl_path("eBPFToSMT/llvm2smt.py")}" '
            f'--input "{wsl_out_dir}/ebpf.bc" '
            f'--output "{wsl_path(smt_file.absolute())}"'
        )
        run_wsl_command(llvm2smt_cmd)

        return str(smt_file)

    except FileNotFoundError as e:
        print(f"Environment setup error: {str(e)}")
        raise
    except subprocess.CalledProcessError as e:
        print(f"Process error: {str(e)}")
        if hasattr(e, 'output'):
            print(f"Command output:\n{e.output}")
        if hasattr(e, 'stderr'):
            print(f"Command stderr:\n{e.stderr}")
        raise
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        raise

def test_environment():
    """Test if the WSL environment is properly set up for eBPF compilation."""
    try:
        print("Testing WSL environment for eBPF compilation...")
        
        # Check if WSL is available
        result = subprocess.run(["wsl", "echo", "WSL is available"], 
                               capture_output=True, text=True, check=True)
        print(f"WSL check: {result.stdout.strip()}")
        
        # Check for clang in WSL
        clang = find_wsl_clang()
        print(f"Found clang in WSL: {clang}")
        
        # Check for required headers
        headers = check_wsl_headers()
        print("\nFound eBPF headers in WSL:")
        for header in headers:
            print(f"- {header}")
            
        print("\nWSL environment is properly configured for eBPF compilation!")
        return True
        
    except Exception as e:
        print(f"\nWSL environment setup failed: {str(e)}")
        return False
