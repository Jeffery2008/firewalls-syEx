# iptablesToSMT/iptables_rule_classes.py
from typing import Dict, List

class IPTablesTable:
    def __init__(self, name: str):
        self.name: str = name
        self.chains: Dict[str, 'IPTablesChain'] = {}

    def __str__(self):
        chains_str = "\\n  ".join(str(chain) for chain in self.chains.values())
        return f"Table(name={self.name}, chains=[\n  {chains_str}\n  ])"

class IPTablesChain:
    def __init__(self, name: str, policy: str = "ACCEPT"):
        self.name: str = name
        self.policy: str = policy
        self.rules: List['IPTablesRule'] = []

    def __str__(self):
        rules_str = "\\n  ".join(str(rule) for rule in self.rules)
        return f"Chain(name={self.name}, policy={self.policy}, rules=[\n  {rules_str}\n  ])"

class IPTablesRule:
    def __init__(self):
        self.table: str = ""
        self.chain: str = ""
        self.proto: str = ""
        self.src_ip: int = 0
        self.src_mask: int = 0
        self.dst_ip: int = 0
        self.dst_mask: int = 0
        self.src_port: str = "0"  # Add source port attribute, default "0" for no port specified
        self.dst_port: str = "0"  # Add destination port attribute, default "0" for no port specified
        self.in_interface: str = ""
        self.out_interface: str = ""
        self.matches: dict = {}
        self.action: str = ""
        self.target_options: List[str] = []

    def __str__(self):
        return f"Rule(table={self.table}, chain={self.chain}, proto={self.proto}, src_ip={self.src_ip}, src_mask={self.src_mask}, dst_ip={self.dst_ip}, dst_mask={self.dst_mask}, in_interface={self.in_interface}, out_interface={self.out_interface}, matches={self.matches}, action={self.action}, target_options={self.target_options})"
