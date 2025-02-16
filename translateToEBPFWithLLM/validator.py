import re
from pathlib import Path
from typing import List, Tuple, Optional

class IptablesValidator:
    # Common iptables commands and options
    VALID_COMMANDS = {'-A', '-I', '-D', '-R', '-P'}
    VALID_TABLES = {'filter', 'nat', 'mangle', 'raw', 'security'}
    VALID_CHAINS = {'INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING'}
    VALID_TARGETS = {'ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN', 'SNAT', 'DNAT', 'MASQUERADE'}
    
    def __init__(self, log_file: Optional[Path] = None):
        """Initialize validator with optional log file."""
        self.log_file = log_file
        self.validation_errors: List[str] = []
        self.validation_warnings: List[str] = []

    def validate_rule(self, rule: str) -> bool:
        """Validate a single iptables rule."""
        # Skip empty lines and comments
        if not rule.strip() or rule.strip().startswith('#'):
            return True
            
        # Basic structure validation
        if not rule.startswith('iptables'):
            self._add_error(f"Rule must start with 'iptables': {rule}")
            return False
            
        # Parse command
        command_match = re.search(r'-[AIRDP]\s+(\w+)', rule)
        if not command_match:
            self._add_error(f"Invalid or missing command in rule: {rule}")
            return False
            
        chain = command_match.group(1)
        if chain not in self.VALID_CHAINS:
            self._add_error(f"Invalid chain '{chain}' in rule: {rule}")
            return False
            
        # Validate targets if present
        target_match = re.search(r'-j\s+(\w+)', rule)
        if target_match and target_match.group(1) not in self.VALID_TARGETS:
            self._add_warning(f"Uncommon target '{target_match.group(1)}' in rule: {rule}")
            
        # Validate protocol if specified
        proto_match = re.search(r'-p\s+(\w+)', rule)
        if proto_match and proto_match.group(1) not in {'tcp', 'udp', 'icmp', 'all'}:
            self._add_warning(f"Uncommon protocol '{proto_match.group(1)}' in rule: {rule}")
            
        return True

    def validate_file(self, input_file: str) -> Tuple[bool, List[str], List[str]]:
        """Validate an iptables rules file."""
        self.validation_errors = []
        self.validation_warnings = []
        
        try:
            with open(input_file, 'r') as f:
                rules = f.readlines()
                
            if not rules:
                self._add_error("Empty rules file")
                return False, self.validation_errors, self.validation_warnings
                
            # Validate each rule
            valid = True
            for line_num, rule in enumerate(rules, 1):
                if not self.validate_rule(rule.strip()):
                    valid = False
                    
            # Check for common structural issues
            if not any('-P' in rule for rule in rules):
                self._add_warning("No default policy (-P) rules found")
                
            if not any(chain in ' '.join(rules) for chain in self.VALID_CHAINS):
                self._add_error("No valid chains found in rules")
                valid = False
                
            # Log validation results
            if self.log_file:
                self._log_validation_results()
                
            return valid, self.validation_errors, self.validation_warnings
            
        except Exception as e:
            self._add_error(f"Error validating file: {str(e)}")
            return False, self.validation_errors, self.validation_warnings

    def _add_error(self, message: str):
        """Add an error message and log it if configured."""
        self.validation_errors.append(message)
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"ERROR: {message}\n")

    def _add_warning(self, message: str):
        """Add a warning message and log it if configured."""
        self.validation_warnings.append(message)
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"WARNING: {message}\n")

    def _log_validation_results(self):
        """Log full validation results to file."""
        with open(self.log_file, 'a') as f:
            f.write("\n=== Validation Results ===\n")
            if self.validation_errors:
                f.write("\nErrors:\n")
                for error in self.validation_errors:
                    f.write(f"- {error}\n")
            if self.validation_warnings:
                f.write("\nWarnings:\n")
                for warning in self.validation_warnings:
                    f.write(f"- {warning}\n")
            f.write("\n")

def validate_iptables_rules(input_file: str, log_file: Optional[str] = None) -> bool:
    """Convenience function to validate iptables rules file."""
    validator = IptablesValidator(Path(log_file) if log_file else None)
    valid, errors, warnings = validator.validate_file(input_file)
    
    if not valid:
        print("\nValidation failed with errors:")
        for error in errors:
            print(f"- {error}")
    if warnings:
        print("\nValidation warnings:")
        for warning in warnings:
            print(f"- {warning}")
            
    return valid
