# iptables_parser.py
from typing import List, Tuple, Optional
from iptables_rule_classes import IPTablesTable, IPTablesChain, IPTablesRule  # Import classes from iptables_rule_classes.py


class IPTablesRule: # Redundant class definition, will be removed
    def __init__(self):
        self.table: str = ""
        self.chain: str = ""
        self.proto: str = ""
        self.src_ip: int = 0
        self.src_mask: int = 0
        self.dst_ip: int = 0
        self.dst_mask: int = 0
        self.in_interface: str = ""
        self.out_interface: str = ""
        self.matches: dict = {} # Changed Dict to dict
        self.action: str = ""
        self.target_options: List[str] = []

    def __str__(self):
        return f"Rule(table={self.table}, chain={self.chain}, proto={self.proto}, src_ip={self.src_ip}, src_mask={self.src_mask}, dst_ip={self.dst_ip}, dst_mask={self.dst_mask}, in_interface={self.in_interface}, out_interface={self.out_interface}, matches={self.matches}, action={self.action}, target_options={self.target_options})"

class IPTablesChain: # Redundant class definition, will be removed
    def __init__(self, name: str, policy: str = "ACCEPT"):
        self.name: str = name
        self.policy: str = policy
        self.rules: List[IPTablesRule] = []

    def __str__(self):
        rules_str = "\n  ".join(str(rule) for rule in self.rules)
        return f"Chain(name={self.name}, policy={self.policy}, rules=[\n  {rules_str}\n  ])"


def parse_ip_and_mask(ip_mask_str: str) -> Tuple[int, int]:
    """Parse IP address and mask from CIDR notation or IP address."""
    if '/' in ip_mask_str:
        ip_str, mask_str = ip_mask_str.split('/')
        mask = int(mask_str)
    else:
        ip_str = ip_mask_str
        mask = 32  # Default mask for single IP address

    parts = ip_str.split('.')
    ip_int = 0
    for part in parts:
        ip_int = (ip_int << 8) | int(part)
    
    return ip_int, mask


def parse_match_options(match_name: str, parts: List[str], start_index: int) -> Tuple[List[str], int]:
    """Parse options for a specific match type."""
    options = []
    i = start_index
    while i < len(parts):
        if parts[i].startswith('-'):
            break  # Next option or action
        options.append(parts[i])
        i += 1
    return options, i


def parse_target_options(parts: List[str], start_index: int) -> Tuple[List[str], int]:
    """Parse target options (e.g., for DNAT, SNAT)."""
    options = []
    i = start_index
    while i < len(parts):
        if parts[i].startswith('-'):
            break  # Next option or action
        options.append(parts[i])
        i += 1
    return options, i


def parse_iptables_save_file(filename: str) -> dict: # Updated return type to dict
    """Parse iptables rules from an iptables-save format file."""
    try:
        with open(filename, 'r') as f:
            content = f.read()
            
        tables: Dict[str, 'IPTablesTable'] = {} # index.py will be updated next
        current_table = None
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            if line.startswith('*'):
                table_name = line[1:].strip()
                current_table = IPTablesTable(table_name) # index.py will be updated next
                tables[table_name] = current_table
                continue
                
            if line.startswith(':'):
                # Chain definition
                parts = line[1:].split()
                chain_name = parts[0]
                policy = parts[1] if len(parts) > 1 else "ACCEPT"
                if current_table:
                    current_table.chains[chain_name] = IPTablesChain(chain_name, policy)
                continue
                
            if line.startswith('COMMIT'):
                current_table = None
                continue
                
            if line.startswith('-A') and current_table:
                rule = IPTablesRule()
                rule.table = current_table.name
                parts = line.split()
                i = 1  # Skip -A
                
                # Get chain name
                rule.chain = parts[i]
                i += 1
                
                while i < len(parts):
                    part = parts[i]
                    
                    if part == '-p':
                        rule.proto = parts[i + 1]
                        i += 2
                    elif part == '-s':
                        rule.src_ip, rule.src_mask = parse_ip_and_mask(parts[i + 1])
                        i += 2
                    elif part == '-d':
                        rule.dst_ip, rule.dst_mask = parse_ip_and_mask(parts[i + 1])
                        i += 2
                    elif part == '-i':
                        rule.in_interface = parts[i + 1]
                        i += 2
                    elif part == '-o':
                        rule.out_interface = parts[i + 1]
                        i += 2
                    elif part in ['--sport', '--source-port']: # Handle source port options
                        port_str = parts[i + 1]
                        if ':' in port_str: # Check if it's a range
                            rule.src_port = port_str.split(':')[0] # Extract only the first port of the range
                        else:
                            rule.src_port = port_str
                        i += 2
                    elif part in ['--dport', '--destination-port']: # Handle destination port options
                        port_str = parts[i + 1]
                        if ':' in port_str: # Check if it's a range
                            rule.dst_port = port_str.split(':')[0] # Extract only the first port of the range
                        else:
                            rule.dst_port = port_str
                        i += 2
                    elif part == '-m':
                        match_name = parts[i + 1]
                        i += 2
                        match_options, i = parse_match_options(match_name, parts, i)
                        rule.matches[match_name] = match_options
                    elif part == '-j':
                        rule.action = parts[i + 1]
                        i += 2
                        if rule.action in ['DNAT', 'SNAT', 'MASQUERADE']:
                            options, i = parse_target_options(parts, i)
                            rule.target_options = options
                    else:
                        i += 1
                
                if rule.chain in current_table.chains:
                    current_table.chains[rule.chain].rules.append(rule)
        
        return tables
        
    except FileNotFoundError:
        raise RuntimeError(f"Could not find iptables rules file: {filename}")
    except Exception as e:
        raise RuntimeError(f"Error parsing iptables rules file: {str(e)}")
