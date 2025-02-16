import os
import sys
import logging
import tkinter as tk
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import json

# Add project components to Python path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.extend([
    str(PROJECT_ROOT / "iptablesToSMT"),
    str(PROJECT_ROOT / "checkConsistency"),
    str(PROJECT_ROOT / "translateToEBPFWithLLM")
])

# Import components
from translateToEBPFWithLLM.main import EBPFTranslator
from translateToEBPFWithLLM.validator import validate_iptables_rules
from translateToEBPFWithLLM.gui import FirewallToolGUI
from iptablesToSMT.main import process_firewall
from checkConsistency.main import check_consistency

# Configure logging
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "firewalls.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FirewallManager:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the firewall manager."""
        self.config = self._load_config(config_path)
        self.translator = EBPFTranslator(model=self.config.get("model"))
        self.output_dir = PROJECT_ROOT / "output"
        self.output_dir.mkdir(exist_ok=True)
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        default_config = {
            "model": "gemini-2.0-flash-thinking-exp-01-21",
            "auto_validate": True,
            "gemini_api_key": os.getenv("GEMINI_API_KEY")
        }
        
        config_dir = PROJECT_ROOT / "config"
        config_dir.mkdir(exist_ok=True)
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
                
        return default_config
        
    def process_rules(self, input_file: str, skip_verify: bool = False) -> Tuple[bool, str]:
        """Process iptables rules through the complete pipeline."""
        try:
            logger.info(f"Starting firewall translation pipeline for {input_file}")
            
            # Step 1: Validate input rules
            logger.info("Validating input rules...")
            if not validate_iptables_rules(input_file):
                logger.error("Input rules validation failed")
                return False, "Input validation failed"
            
            # Step 2: Generate eBPF code using LLM
            logger.info("Translating to eBPF...")
            ebpf_file = self.translator.translate_rules(input_file)
            ebpf_path = self.output_dir / Path(ebpf_file).name
            
            if not ebpf_path.exists():
                logger.error("eBPF translation failed")
                return False, "Translation failed"
                
            if skip_verify:
                return True, str(ebpf_path)
            
            # Step 3: Generate SMT formulas
            logger.info("Generating SMT formulas...")
            
            # Generate SMT for input iptables rules
            iptables_smt = self.output_dir / f"{Path(input_file).stem}_iptables.smt2"
            process_firewall(input_file, str(iptables_smt))
            
            # Generate SMT for translated eBPF code
            ebpf_smt = self.output_dir / f"{Path(ebpf_file).stem}_ebpf.smt2"
            process_firewall(str(ebpf_path), str(ebpf_smt))
            
            # Step 4: Verify equivalence
            logger.info("Verifying equivalence...")
            is_consistent, message = check_consistency(str(iptables_smt), str(ebpf_smt))
            
            if is_consistent:
                logger.info("✓ Verification successful: Rules are equivalent")
                return True, str(ebpf_path)
            else:
                logger.warning(f"⚠ Verification warning: {message}")
                return False, f"Verification failed: {message}"
                
        except Exception as e:
            logger.error(f"Pipeline error: {str(e)}")
            return False, str(e)
            
    def start_gui(self):
        """Launch the GUI interface."""
        root = tk.Tk()
        app = FirewallToolGUI(root)
        root.mainloop()

def main():
    """Command line entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="IPTables to eBPF Translation Tool")
    parser.add_argument("--config", help="Path to configuration file")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Setup command
    setup_parser = subparsers.add_parser("config", help="Configure settings")
    setup_parser.add_argument("--api-key", required=True, help="Google Gemini API key")
    setup_parser.add_argument("--model", help="Model name (optional)")
    
    # GUI command
    subparsers.add_parser("gui", help="Launch GUI interface")
    
    # Translate command
    translate_parser = subparsers.add_parser("translate", help="Translate iptables rules")
    translate_parser.add_argument("input", help="Input rules file")
    translate_parser.add_argument("--skip-verify", action="store_true", help="Skip verification")
    
    args = parser.parse_args()
    
    manager = FirewallManager(args.config)
    
    if args.command == "config":
        config = {
            "gemini_api_key": args.api_key,
            "model": args.model or "gemini-2.0-flash-thinking-exp-01-21"
        }
        config_path = PROJECT_ROOT / "config/settings.json"
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"Configuration saved to {config_path}")
        
    elif args.command == "gui":
        manager.start_gui()
        
    elif args.command == "translate":
        success, result = manager.process_rules(args.input, args.skip_verify)
        if success:
            print(f"\nSuccess! Output saved to: {result}")
            sys.exit(0)
        else:
            print(f"\nError: {result}")
            sys.exit(1)
            
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
