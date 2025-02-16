import google.generativeai as genai
from pathlib import Path
import sys
import subprocess
import json
import shutil
from config import load_config

def setup_gemini():
    """Setup Gemini API with configuration."""
    config = load_config()
    if not config["gemini_api_key"]:
        raise ValueError("Gemini API key not configured. Please set it using the configuration.")
    
    genai.configure(api_key=config["gemini_api_key"])
    generation_config = {
        "temperature": config["temperature"],
        "max_output_tokens": config["max_output_tokens"],
    }
    
    # Add top_k and top_p if present in config
    if "top_k" in config:
        generation_config["top_k"] = config["top_k"]
    if "top_p" in config:
        generation_config["top_p"] = config["top_p"]
    
    model = genai.GenerativeModel(
        model_name=config["gemini_model"],
        generation_config=generation_config
    )
    return model

def read_iptables_rules(file_path):
    """Read iptables rules from file."""
    with open(file_path, 'r') as f:
        return f.read()

def convert_to_ebpf(model, iptables_rules):
    """Convert iptables rules to eBPF using Gemini."""
    prompt = f"""You are a FireMason expert specializing in network security rule conversion. Your task is to convert iptables firewall rules to semantically equivalent eBPF code for Traffic Control (TC).

Follow this structured approach:
1. Parse and understand the iptables rules packet filtering logic
2. Convert each rule to equivalent TC eBPF code while preserving semantics
3. Maintain connection tracking and state handling if present
4. Use TC classifier hook points (cls_bpf) for the filters

Technical Requirements:
- Use struct __sk_buff context for TC classifier
- Include necessary headers for tc-bpf (bpf.h, if_ether.h, ip.h, etc)
- Implement Linux kernel's TC BPF extension for filtering
- Keep exact filtering behavior and security properties
- Create efficient BPF maps for stateful filtering if needed
- Follow eBPF best practices for TC filters
- Support common iptables matches (protocol, ports, addresses)

Input iptables rules:
{iptables_rules}

Return complete, compilable eBPF C code (tc-bpf) without explanations."""

    response = model.generate_content(prompt)
    return response.text

def convert_ebpf_to_smt(ebpf_code):
    """Convert eBPF code to SMT expressions using LLVM and Z3."""
    from ebpf_to_smt import generate_smt_from_ebpf
    
    try:
        smt_file = generate_smt_from_ebpf(ebpf_code)
        print(f"Successfully converted eBPF to SMT formula: {smt_file}")
        return smt_file
    except subprocess.CalledProcessError as e:
        print(f"Error converting eBPF to SMT: {e}")
        raise

def verify_conversion(iptables_rules_file, ebpf_smt_file):
    """Verify the conversion using SMT solver."""
    # Convert iptables to SMT using existing tool
    iptables_smt_file = "iptables.smt2"
    subprocess.run([
        "python", 
        "iptablesToSMT/main.py",
        "--input", iptables_rules_file,
        "--output", iptables_smt_file
    ], check=True)
    
    # Use checkConsistency tool to verify
    result = subprocess.run([
        "python",
        "checkConsistency/main.py",
        iptables_smt_file,
        ebpf_smt_file
    ], capture_output=True, text=True)
    
    return {
        "verified": result.returncode == 0,
        "output": result.stdout,
        "error": result.stderr if result.returncode != 0 else None
    }

def convert_and_verify(input_file, max_attempts=3):
    """Main function to convert iptables to eBPF and verify with automatic retry."""
    attempts = 0
    while attempts < max_attempts:
        try:
            attempts += 1
            print(f"\n🔄 Attempt {attempts} of {max_attempts}")

            # Setup Gemini model
            model = setup_gemini()

            # 1. iptables firewall (Input iptables rules)
            iptables_rules = read_iptables_rules(input_file)

            # 2. FireMason (Convert iptables to SMT Formula)
            print("Converting iptables to SMT Formula...")
            # Create temporary directory structure for iptablesToSMT
            temp_input_dir = Path("temp_input")
            temp_output_dir = Path("temp_output")
            temp_input_dir.mkdir(exist_ok=True)
            temp_output_dir.mkdir(exist_ok=True)
            
            # Copy input file to temp directory
            temp_input_file = temp_input_dir / "rules.txt"
            shutil.copy2(input_file, temp_input_file)
            
            # Run iptablesToSMT
            subprocess.run([
                "python",
                "iptablesToSMT/main.py",
                str(temp_input_dir),
                str(temp_output_dir)
            ], check=True)
            
            # Find the generated SMT file
            iptables_smt_file = str(temp_output_dir / "rules" / "output.smt2")

            # 3. LLM Optimization (Translate iptables to eBPF with Gemini)
            print("Translating iptables to optimized eBPF using Gemini...")
            ebpf_code = convert_to_ebpf(model, iptables_rules)

            # Save eBPF code to file
            ebpf_file_path = Path(f"output_ebpf_attempt_{attempts}.c")
            ebpf_file_path.write_text(ebpf_code)
            ebpf_file = str(ebpf_file_path)
            print(f"eBPF code saved to {ebpf_file}")

            # 4. FireMason (Convert eBPF to SMT Formula)
            print("Converting eBPF to SMT Formula...")
            ebpf_smt_file = convert_ebpf_to_smt(ebpf_code)
            print(f"eBPF SMT formula saved to {ebpf_smt_file}")

            # 5. Compare (Verify equivalence of SMT formulas)
            print("Verifying equivalence using SMT Solver...")
            verification_result = verify_conversion(iptables_smt_file, ebpf_smt_file)

            if verification_result["verified"]:
                print(f"✅ Verification successful on attempt {attempts}!")
                print("IPTables and eBPF rules are semantically equivalent.")
                return verification_result
            else:
                print(f"❌ Verification failed on attempt {attempts}")
                if verification_result["error"]:
                    print("Error details:\n", verification_result["error"])
                
                if attempts == max_attempts:
                    print("❌ Max attempts reached. Could not generate equivalent eBPF code.")
                    return verification_result
                else:
                    print("🔄 Retrying with modified prompt...")
                    continue

        except Exception as e:
            print(f"🔥 Error during attempt {attempts}: {e}")
            if attempts == max_attempts:
                raise e
            print("🔄 Retrying...")
            continue

    return {"verified": False, "error": "Max attempts reached without success"}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python gemini_converter.py <iptables_rules_file>")
        sys.exit(1)
        
    convert_and_verify(sys.argv[1])
