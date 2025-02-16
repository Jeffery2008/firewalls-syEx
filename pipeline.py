import os
import sys
import subprocess
from pathlib import Path

def convert_iptables_to_smt(rules_file):
    """Convert iptables rules to SMT formula using iptablesToSMT tool."""
    # Use the existing iptablesToSMT tool
    try:
        subprocess.run(
            ["python", "iptablesToSMT/main.py", rules_file],
            check=True
        )
        return "output.smt2"  # The tool outputs to this file
    except subprocess.CalledProcessError as e:
        print(f"Error converting iptables to SMT: {e}")
        raise

def convert_iptables_to_ebpf(rules_file, api_key=None, model="gemini-pro"):
    """Convert iptables rules to eBPF using Worker API."""
    import requests
    import os

    # Get API URL from environment or use default Cloudflare Worker URL
    api_url = os.getenv("GEMINI_WORKER_URL", "https://gemini-worker.your-subdomain.workers.dev")
    
    with open(rules_file, 'r') as f:
        rules = f.read()
    
    try:
        # Call the Worker API endpoint
        response = requests.post(
            f"{api_url}/translate",
            json={
                "rules": rules,
                "model": model
            },
            headers={
                # Pass API key in header if provided
                **({"X-Gemini-API-Key": api_key} if api_key else {})
            }
        )
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            raise Exception(data["error"])
        
        if "code" not in data:
            raise Exception("No code returned from API")
            
        # Save the eBPF code to a file
        ebpf_file = "output.c"
        with open(ebpf_file, "w") as f:
            f.write(data["code"])
            
        return ebpf_file
        
    except requests.exceptions.RequestException as e:
        print(f"Error calling Worker API: {e}")
        raise
    except Exception as e:
        print(f"Error converting iptables to eBPF: {e}")
        raise

def convert_ebpf_to_smt(ebpf_file):
    """Convert eBPF program to SMT formula."""
    from ebpf_to_smt import generate_smt_from_ebpf
    
    with open(ebpf_file, 'r') as f:
        ebpf_code = f.read()
    
    try:
        smt_file = generate_smt_from_ebpf(ebpf_code)
        return smt_file
    except Exception as e:
        print(f"Error converting eBPF to SMT: {e}")
        raise

def verify_consistency(smt1, smt2):
    """Verify consistency between two SMT formulas using checkConsistency tool."""
    try:
        result = subprocess.run(
            ["python", "checkConsistency/main.py", smt1, smt2],
            capture_output=True,
            text=True,
            check=True
        )
        return "Consistent" in result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error verifying consistency: {e}")
        raise

def convert_and_verify(rules_file, api_key, model="gemini-pro", max_attempts=3):
    """Main pipeline to convert iptables to eBPF and verify consistency."""
    for attempt in range(max_attempts):
        print(f"\n🔄 Attempt {attempt + 1} of {max_attempts}")
        
        try:
            print("Converting iptables to SMT Formula...")
            iptables_smt = convert_iptables_to_smt(rules_file)
            
            print("Translating iptables to optimized eBPF using Gemini...")
            ebpf_file = convert_iptables_to_ebpf(rules_file, api_key, model)
            print(f"eBPF code saved to {ebpf_file}")
            
            print("Converting eBPF to SMT Formula...")
            ebpf_smt = convert_ebpf_to_smt(ebpf_file)
            
            print("Verifying equivalence...")
            if verify_consistency(iptables_smt, ebpf_smt):
                print("✅ Success! The eBPF implementation is equivalent to the original iptables rules.")
                return ebpf_file
            else:
                print("❌ The implementations are not equivalent. Retrying with different translation...")
        
        except Exception as e:
            print(f"🔥 Error during attempt {attempt + 1}: {str(e)}")
            if attempt < max_attempts - 1:
                print("🔄 Retrying...")
            else:
                raise e

    raise Exception("Failed to generate equivalent eBPF implementation after maximum attempts")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pipeline.py <rules_file> <api_key> [model]")
        sys.exit(1)
        
    rules_file = sys.argv[1]
    api_key = sys.argv[2]
    model = sys.argv[3] if len(sys.argv) > 3 else "gemini-pro"
    
    convert_and_verify(rules_file, api_key, model)
