#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path
from config import update_config, load_config
from gemini_converter import convert_and_verify

def setup_config(args):
    """Setup or update configuration."""
    if args.api_key:
        update_config(api_key=args.api_key)
    if args.model:
        update_config(model=args.model)
    if args.temperature is not None:
        update_config(temperature=args.temperature)
    if args.max_tokens is not None:
        update_config(max_tokens=args.max_tokens)
    
    # Verify configuration
    config = load_config()
    if not config["gemini_api_key"]:
        print("Error: Gemini API key not configured. Use --api-key to set it.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Convert iptables rules to eBPF and verify using SMT solver")
    
    # Configuration arguments
    parser.add_argument("--api-key", help="Set Gemini API key")
    parser.add_argument("--model", help="Set Gemini model (default: gemini-pro)", 
                      choices=["gemini-pro", "gemini-pro-vision"])
    parser.add_argument("--temperature", type=float, help="Set temperature (0.0 to 1.0)")
    parser.add_argument("--max-tokens", type=int, help="Set maximum output tokens")
    
    # Operation arguments
    parser.add_argument("--input", "-i", help="Input iptables rules file")
    parser.add_argument("--output-dir", "-o", help="Output directory for generated files", 
                      default="output")
    
    args = parser.parse_args()
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    # Setup configuration if needed
    setup_config(args)
    
    # Create output directory
    if args.output_dir:
        Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Convert and verify if input file provided
    if args.input:
        try:
            result = convert_and_verify(args.input)
            if not result["verified"]:
                sys.exit(1)
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()
