from iptables_rule_classes import IPTablesRule

def generate_c_code(tables, output_file):
    """Generate C code from the parsed iptables rules"""

    # Protocol number mapping
    proto_map = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
        "icmpv6": 58,
        "any": -1
    }

    # Start with SMT-LIB header
    c_code = """(set-logic QF_BV)

;; Declare variables for packet attributes
(declare-fun src_ip () (_ BitVec 32))
(declare-fun dst_ip () (_ BitVec 32))
(declare-fun src_port () (_ BitVec 16))
(declare-fun dst_port () (_ BitVec 16))
(declare-fun proto () (_ BitVec 8))
(declare-fun state () (_ BitVec 8))

;; Declare constants for actions
(declare-const ACTION_DROP (_ BitVec 8))
(declare-const ACTION_ACCEPT (_ BitVec 8))

;; Define values for actions (example - adjust as needed)
(assert (= ACTION_DROP #b00000000))  ; Example: 0 for DROP
(assert (= ACTION_ACCEPT #b00000001)) ; Example: 1 for ACCEPT

;; Function to apply mask (bitwise AND)
(define-fun apply_mask ((ip (_ BitVec 32)) (mask (_ BitVec 32))) (_ BitVec 32)
    (bvand ip mask)
)

;; Define init_rules function - will contain rule assertions
(define-fun init_rules () ()
  ; Initialize rules - assertions will go here
"""

    rule_idx = 0

    # Process filter table rules in sequence
    if 'filter' in tables:
        filter_table = tables['filter']

        # Process chains in the correct order
        chain_sequence = [
            'ufw-before-input',
            'ufw-user-input',
            'ufw-after-input',
            'INPUT'  # Default chain
        ]

        for chain_name in chain_sequence:
            if chain_name in filter_table.chains:
                chain = filter_table.chains[chain_name]
                for rule in chain.rules:
                    # Skip only logging rules and jumps to UFW logging/tracking chains
                    if (rule.action in ['LOG', 'LOGGING', 'LOGGING_FORWARD'] or
                        any(x in rule.action for x in [
                            'ufw-logging',
                            'ufw-track',
                            'ufw-before-logging',
                            'ufw-after-logging',
                            'ufw-skip-to-policy'
                        ])):
                        continue

                    # Rule conditions - SMT-LIB assertions will be built here
                    rule_conditions = []

                    # Protocol condition
                    if rule.proto != "any":
                        protocol_bv = f"#b{proto_map.get(rule.proto.lower(), -1):08b}"
                        rule_conditions.append(f"(= proto {protocol_bv})")

                    # Source IP and Mask condition
                    if rule.src_ip != "any":
                        src_ip_bv = f"#x{int(ip_to_int(rule.src_ip)):08x}"
                        src_mask_bv = f"#x{int(cidr_to_mask(rule.src_mask)):08x}" if rule.src_mask else "#xffffffff"
                        rule_conditions.append(f"(= (apply_mask src_ip {src_mask_bv}) (apply_mask {src_ip_bv} {src_mask_bv}))")

                    # Destination IP and Mask condition
                    if rule.dst_ip != "any":
                        dst_ip_bv = f"#x{int(ip_to_int(rule.dst_ip)):08x}"
                        dst_mask_bv = f"#x{int(cidr_to_mask(rule.dst_mask)):08x}" if rule.dst_mask else "#xffffffff"
                        rule_conditions.append(f"(= (apply_mask dst_ip {dst_mask_bv}) (apply_mask {dst_ip_bv} {dst_mask_bv}))")

                    # Source Port condition
                    if hasattr(rule, 'src_port') and rule.src_port != "0": 
                        sport_bv = f"#x{int(rule.src_port):04x}" 
                        rule_conditions.append(f"(= src_port {sport_bv})")

                    # Destination Port condition
                    if hasattr(rule, 'dst_port') and rule.dst_port != "0": 
                        dport_bv = f"#x{int(rule.dst_port):04x}" 
                        rule_conditions.append(f"(= dst_port {dport_bv})")


                    # Combine all conditions with 'and'
                    if rule_conditions:
                        combined_condition = "(and " + " ".join(rule_conditions) + ")"
                    else:
                        combined_condition = "true" # No conditions, always match

                    smt_assertion = f"(assert {combined_condition})"


                    c_code += f"  ; Rule {rule_idx + 1} assertion\n" # SMT-LIB comment
                    c_code += smt_assertion + "\\n\\n"

                    rule_idx += 1

        # Add default DROP policy rule at the end - SMT-LIB assertion for default DROP will be added later
        c_code += f"  ; Default DROP policy assertion (will be added later)\\n"
        rule_idx += 1

    c_code += f"  ; Total rules count: {rule_idx}\\n" # SMT-LIB comment
    c_code += ")}\\n\\n" # Closing parenthesis for define-fun init_rules

    # Add default DROP policy assertion in init_rules function
    c_code += ";; Assert default DROP policy for filter table (if no rule matches)\n"
    c_code += ";; (No explicit assertion needed here, default DROP is handled in check_packet function)\n\n"


    # Add enhanced packet checking function - SMT-LIB version
    # Initialize check_packet function string
    check_packet_code = """
;; Define check_packet function - SMT-LIB version
(define-fun check_packet ((src_ip (_ BitVec 32)) (dst_ip (_ BitVec 32)) (src_port (_ BitVec 16)) (dst_port (_ BitVec 16)) (proto (_ BitVec 8)) (state () (_ BitVec 8))) (_ BitVec 8)
  (let (
"""
    rule_actions_let_body = ""
    last_action = "ACTION_DROP" # Default action if no rule matches

    rule_idx = 0
    # Process filter table rules in sequence - again (similar to init_rules)
    if 'filter' in tables:
        filter_table = tables['filter']
        chain_sequence = ['ufw-before-input', 'ufw-user-input', 'ufw-after-input', 'INPUT']

        for chain_name in chain_sequence:
            if chain_name in filter_table.chains:
                chain = filter_table.chains[chain_name]
                for rule in chain.rules:
                    if (rule.action in ['LOG', 'LOGGING', 'LOGGING_FORWARD'] or
                        any(x in rule.action for x in ['ufw-logging', 'ufw-track', 'ufw-before-logging', 'ufw-after-logging', 'ufw-skip-to-policy'])):
                        continue

                    rule_conditions_check_packet = []

                    # Protocol condition
                    if rule.proto != "any":
                        protocol_bv = f"#b{proto_map.get(rule.proto.lower(), -1):08b}"
                        rule_conditions_check_packet.append(f"(= proto {protocol_bv})")

                    # Source IP and Mask condition
                    if rule.src_ip != "any":
                        src_ip_bv = f"#x{int(ip_to_int(rule.src_ip)):08x}"
                        src_mask_bv = f"#x{int(cidr_to_mask(rule.src_mask)):08x}" if rule.src_mask else "#xffffffff"
                        rule_conditions_check_packet.append(f"(= (apply_mask src_ip {src_mask_bv}) (apply_mask {src_ip_bv} {src_mask_bv}))")

                    # Destination IP and Mask condition
                    if rule.dst_ip != "any":
                        dst_ip_bv = f"#x{int(ip_to_int(rule.dst_ip)):08x}"
                        dst_mask_bv = f"#x{int(cidr_to_mask(rule.dst_mask)):08x}" if rule.dst_mask else "#xffffffff"
                        rule_conditions_check_packet.append(f"(= (apply_mask dst_ip {dst_mask_bv}) (apply_mask {dst_ip_bv} {dst_mask_bv}))")

                    # Source Port condition (range) - check for attribute existence in check_packet as well
                    if hasattr(rule, 'src_port') and rule.src_port != "0":
                        sport_bv = f"#x{int(rule.src_port):04x}"
                        if hasattr(rule, 'src_port_high'):
                            sport_high_bv = f"#x{int(rule.src_port_high):04x}"
                            if hasattr(rule, 'src_port_high') and rule.src_port == rule.src_port_high:
                                rule_conditions_check_packet.append(f"(= src_port {sport_bv})")
                            elif hasattr(rule, 'src_port_high'):
                                rule_conditions_check_packet.append(f"(and (bvsge src_port {sport_bv}) (bvsle src_port {sport_high_bv}))")
                        else:
                             rule_conditions_check_packet.append(f"(= src_port {sport_bv})")

                    # Destination Port condition (range) - check for attribute existence in check_packet as well
                    if hasattr(rule, 'dst_port') and rule.dst_port != "0":
                        dport_bv = f"#x{int(rule.dst_port):04x}"
                        if hasattr(rule, 'dst_port_high'):
                            dport_high_bv = f"#x{int(rule.dst_port_high):04x}"
                            if hasattr(rule, 'dst_port_high') and rule.dst_port == rule.dst_port_high:
                                rule_conditions_check_packet.append(f"(= dst_port {dport_bv})")
                            elif hasattr(rule, 'dst_port_high'):
                                rule_conditions_check_packet.append(f"(and (bvsge dst_port {dport_bv}) (bvsle dst_port {dport_high_bv}))")
                        else:
                            rule_conditions_check_packet.append(f"(= dst_port {dport_bv})")

                    # Combine conditions for check_packet rule
                    if rule_conditions_check_packet:
                        combined_condition_check_packet = "(and " + " ".join(rule_conditions_check_packet) + ")"
                    else:
                        combined_condition_check_packet = "true"

                    rule_action_name = f"action_rule{rule_idx}"
                    rule_actions_let_body += f"""
    ({rule_action_name} (ite  ; Rule {rule_idx + 1}
        {combined_condition_check_packet}
        ACTION_ACCEPT
        {last_action} ; Fallback to previous rule's action if not matched
    ))
"""
                    last_action = rule_action_name # Update last_action for next rule
                    rule_idx += 1


    check_packet_code += rule_actions_let_body
    check_packet_code += f"""
    (action_default ACTION_DROP) ; Default action if no rule matches
    )
    (ite {last_action} ; Evaluate last rule's action (which chains back to previous rules)
         {last_action}
         action_default)
  )
)
"""
    c_code += check_packet_code

    # End of SMT-LIB file
    c_code += """
;; End of SMT-LIB file
)
"""

    # Write the generated code to file
    with open(output_file, 'w') as f:
        f.write(c_code)
    return c_code


def ip_to_int(ip_str):
    """Convert an IP address string to an integer"""
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return 0
        return sum(int(part) << (24 - 8 * i) for i, part in enumerate(parts))
    except:
        return 0


def cidr_to_mask(cidr_str):
    """Convert CIDR notation to netmask"""
    try:
        bits = int(cidr_str)
        return (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    except:
        return 0xFFFFFFFF
