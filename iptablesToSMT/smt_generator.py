# iptablesToSMT/smt_generator.py

def generate_smtlib_from_tables(tables):
    """
    Generates SMT-LIB expressions from parsed iptables tables.
    """
    smtlib_code = ""
    smtlib_code += "(set-logic ALL_SUPPORTED)\n"  # Set logic at the beginning

    for table_name, table in tables.items():
        smtlib_code += f";; Table: {table_name}\n"
        for chain_name, chain in table.chains.items():
            smtlib_code += f";; Chain: {chain_name} (policy: {chain.policy})\n"
            for rule in chain.rules:
                rule_str = str(rule).replace("\n", " ")  # avoid newlines in comment
                smtlib_code += f";; Rule: {rule_str}\n"
                # TODO: Generate actual SMT-LIB assertions for each rule here

    return smtlib_code


if __name__ == "__main__":
    # Example usage (for testing purposes)
    # You might want to parse example.rules and then call generate_smtlib_from_tables
    # For now, just a placeholder:
    print("smt_generator.py running (placeholder)")

    class MockIPTablesTable:  # Mock class for testing
        def __init__(self, name):
            self.name = name
            self.chains = {}

    class MockIPTablesChain:
        def __init__(self, name, policy="ACCEPT"):
            self.name = name
            self.policy = policy
            self.rules = []

    class MockIPTablesRule:
        def __init__(self, table, chain, proto, dport, action):
            self.table = table
            self.chain = chain
            self.proto = proto
            self.dport = dport
            self.action = action

        def __str__(self):
            return (
                f"MockRule(table={self.table}, chain={self.chain}, proto={self.proto}, "
                f"dport={self.dport}, action={self.action})"
            )

    mock_tables = {"filter": MockIPTablesTable("filter")}
    mock_tables["filter"].chains["INPUT"] = MockIPTablesChain("INPUT", policy="DROP")
    mock_tables["filter"].chains["INPUT"].rules.append(
        MockIPTablesRule(table="filter", chain="INPUT", proto="tcp", dport="22", action="ACCEPT")
    )
    mock_tables["filter"].chains["INPUT"].rules.append(
        MockIPTablesRule(table="filter", chain="INPUT", proto="tcp", dport="80", action="ACCEPT")
    )

    smtlib_output = generate_smtlib_from_tables(mock_tables)  # Example mock tables
    print("\nSMT-LIB Output:\n", smtlib_output)
