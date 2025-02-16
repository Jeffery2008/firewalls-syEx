import json
import ipaddress
import argparse

def json_to_ebpf_script(json_data):
    """
    Converts the structured iptables JSON to a basic eBPF C code script (TC version).

    Args:
        json_data:  A JSON string or a Python dictionary representing the iptables rules.

    Returns:
        A string containing the generated eBPF C code script (TC version).
    """

    if isinstance(json_data, str):
        try:
            iptables_json = json.loads(json_data)
        except json.JSONDecodeError as e:
            return f"Error decoding JSON: {e}"
    elif isinstance(json_data, dict):
        iptables_json = json_data
    else:
        return "Input must be a JSON string or a Python dictionary."

    ebpf_code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define IP_PROTO_ICMP 1

// Define any necessary maps here (for NAT, counters, interface indices, etc.)
// struct bpf_map_def SEC("maps") my_map = { ... };

SEC("tc")
int iptables_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    int ip_header_len;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK; // Pass to next handler

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // Only process IP packets

    iph = data + sizeof(*eth);
    if (iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    ip_header_len = iph->ihl * 4;
    if (data + sizeof(*eth) + ip_header_len > data_end)
        return TC_ACT_OK;

    // Protocol Check
    if (iph->protocol == IP_PROTO_TCP) {
        tcph = (struct tcphdr *)((void *)iph + ip_header_len);
        if (tcph + sizeof(*tcph) > data_end)
            return TC_ACT_OK;
    } else if (iph->protocol == IP_PROTO_UDP) {
        udph = (struct udphdr *)((void *)iph + ip_header_len);
        if (udph + sizeof(*udph) > data_end)
            return TC_ACT_OK;
    } else if (iph->protocol == IP_PROTO_ICMP) {
        icmph = (struct icmphdr *)((void *)iph + ip_header_len);
        if (icmph + sizeof(*icmph) > data_end)
            return TC_ACT_OK;
    }

"""

    default_policies = {} # Store default policies for filter chains
    for rule_data in iptables_json.get("iptables_rules", []):
        table = rule_data.get("table")
        chain = rule_data.get("chain")
        rule_str = rule_data.get("rule", "")

        ebpf_code += f"\n    // --- iptables rule: {rule_str} (Table: {table}, Chain: {chain}) --- \n"

        if "policy" in rule_data:
            default_policies[(table, chain)] = rule_data["policy"]
            ebpf_code += f"    // Chain Policy: {rule_data['policy']}\n"
            continue # Policy rules are handled at the end

        conditions = []

        # Protocol
        protocol = rule_data.get("protocol")
        if protocol == "tcp":
            conditions.append("iph->protocol == IP_PROTO_TCP")
        elif protocol == "udp":
            conditions.append("iph->protocol == IP_PROTO_UDP")
        elif protocol == "icmp":
            conditions.append("iph->protocol == IP_PROTO_ICMP")
        elif protocol == "all":
            pass # No protocol condition

        # Source IP/Network
        source = rule_data.get("source")
        if source:
            try:
                ip_network = ipaddress.ip_network(source, strict=False)
                ip_addr_int = int(ip_network.network_address)
                ip_mask_int = int(ip_network.netmask)
                negate_source = rule_data.get("negate_source", False)
                condition = f"(iph->saddr & bpf_htonl({ip_mask_int})) == bpf_htonl({ip_addr_int})"
                if negate_source:
                    condition = f"!({condition})"
                conditions.append(condition)
            except ValueError:
                ebpf_code += f"    // WARNING: Invalid source IP/network: {source}\n"

        # Destination IP/Network
        destination = rule_data.get("destination")
        if destination:
            try:
                ip_network = ipaddress.ip_network(destination, strict=False)
                ip_addr_int = int(ip_network.network_address)
                ip_mask_int = int(ip_network.netmask)
                negate_destination = rule_data.get("negate_destination", False)
                condition = f"(iph->daddr & bpf_htonl({ip_mask_int})) == bpf_htonl({ip_addr_int})"
                if negate_destination:
                    condition = f"!({condition})"
                conditions.append(condition)
            except ValueError:
                ebpf_code += f"    // WARNING: Invalid destination IP/network: {destination}\n"

        # In Interface
        in_interface = rule_data.get("in_interface")
        if in_interface:
            negate_in_interface = rule_data.get("negate_in_interface", False)
            condition = f"skb->ifindex == ifindex_{in_interface}" # Assuming ifindex_INTERFACE maps are defined
            if negate_in_interface:
                condition = f"!({condition})"
            conditions.append(condition)
            ebpf_code += f"    // WARNING: Interface matching requires pre-defined interface index map: ifindex_{in_interface}\n"

        # Out Interface
        out_interface = rule_data.get("out_interface")
        if out_interface:
            negate_out_interface = rule_data.get("negate_out_interface", False)
            condition = f"skb->ifindex == ifindex_{out_interface}" # Assuming ifindex_INTERFACE maps are defined
            if negate_out_interface:
                condition = f"!({condition})"
            conditions.append(condition)
            ebpf_code += f"    // WARNING: Interface matching requires pre-defined interface index map: ifindex_{out_interface}\n"


        # Matches (modules)
        matches = rule_data.get("matches", [])
        for match in matches:
            module = match.get("module")
            match_type = match.get("match")
            value = match.get("value")

            if module == "tcp" or module == "udp":
                if match_type == "--dport":
                    try:
                        port = int(value)
                        conditions.append(f"{module}h->dest == bpf_htons({port})")
                    except ValueError:
                        ebpf_code += f"    // WARNING: Invalid port value: {value} for module {module}\n"
                elif match_type == "--sport":
                    try:
                        port = int(value)
                        conditions.append(f"{module}h->source == bpf_htons({port})")
                    except ValueError:
                        ebpf_code += f"    // WARNING: Invalid port value: {value} for module {module}\n"
                elif module == "state" and match_type == "--state":
                    ebpf_code += f"    // WARNING: Conntrack state matching ({value}) is complex in eBPF and requires connection tracking helpers.\n"
                elif module == "icmp" and match_type == "--icmp-type":
                    try:
                        icmp_type = int(value)
                        conditions.append(f"icmph->type == {icmp_type}")
                    except ValueError:
                         ebpf_code += f"    // WARNING: Invalid icmp-type value: {value} for module icmp\n"
                elif module == "addrtype" and match_type == "--dst-type" and value == "LOCAL":
                    ebpf_code += f"    // WARNING: addrtype --dst-type LOCAL is complex and requires checking against local address ranges.\n"
            elif module == "state" and match_type == "--state": # Redundant, already handled inside tcp/udp module handling but kept for clarity
                 ebpf_code += f"    // WARNING: Conntrack state matching ({value}) is complex and requires connection tracking helpers.\n"


        # Target Action
        target = rule_data.get("target")
        action = "TC_ACT_OK" # Default action if no target matched (should not happen for valid rules)
        if target == "ACCEPT":
            action = "TC_ACT_OK"
        elif target == "DROP":
            action = "TC_ACT_SHOT"
        elif target == "MASQUERADE":
            ebpf_code += f"    // WARNING: MASQUERADE target is complex in eBPF and requires NAT helpers and connection tracking.\n"
            action = "TC_ACT_OK" # Placeholder, actual MASQUERADE needs more logic
        elif target == "DNAT":
            ebpf_code += f"    // WARNING: DNAT target is complex in eBPF and requires NAT helpers and connection tracking.\n"
            action = "TC_ACT_OK" # Placeholder, actual DNAT needs more logic
        elif target == "LOG":
            log_prefix = rule_data.get("target_options", {}).get("log_prefix", "IPTables-Log: ")
            log_prefix_escaped = log_prefix.replace('"', '\\"') # Escape quotes for C string
            ebpf_code += f'    bpf_printk("{log_prefix_escaped} SRC:%pI4:%d DST:%pI4:%d\\n", &iph->saddr, (iph->protocol == IP_PROTO_TCP) ? tcph->source : udph->source, &iph->daddr, (iph->protocol == IP_PROTO_TCP) ? tcph->dest : udph->dest);\n'
            action = "TC_ACT_OK" # LOG action usually continues processing, adjust if needed


        # Combine conditions and action
        if conditions:
            ebpf_code += f"    if ({' && '.join(conditions)}) {{\n"
            ebpf_code += f"        return {action};\n"
            ebpf_code += "    }\n"
        else:
            ebpf_code += f"    // No conditions specified, applying target action directly: {target}\n"
            ebpf_code += f"    return {action};\n"


    # Handle default chain policies (for filter table - INPUT, FORWARD, OUTPUT)
    filter_default_policy_input = default_policies.get(("filter", "INPUT"))
    filter_default_policy_forward = default_policies.get(("filter", "FORWARD"))
    filter_default_policy_output = default_policies.get(("filter", "OUTPUT"))

    ebpf_code += "\n    // --- Default Chain Policies --- \n"
    if filter_default_policy_input == "DROP":
        ebpf_code += "    // Filter INPUT chain default policy: DROP\n"
        ebpf_code += "    if (skb->pkt_type == PACKET_HOST) { // Check if packet is for local host (INPUT chain)\n"
        ebpf_code += "        bpf_printk(\"Filter INPUT chain default DROP: SRC:%pI4:%d DST:%pI4:%d\\n\", &iph->saddr, (iph->protocol == IP_PROTO_TCP) ? tcph->source : udph->source, &iph->daddr, (iph->protocol == IP_PROTO_TCP) ? tcph->dest : udph->dest);\n"
        ebpf_code += "        return TC_ACT_SHOT;\n"
        ebpf_code += "    }\n"
    if filter_default_policy_forward == "DROP":
        ebpf_code += "    // Filter FORWARD chain default policy: DROP\n"
        ebpf_code += "    if (skb->pkt_type != PACKET_HOST && skb->pkt_type != PACKET_OTHERHOST) { // Check if packet is being forwarded (FORWARD chain)\n"
        ebpf_code += "        bpf_printk(\"Filter FORWARD chain default DROP: SRC:%pI4:%d DST:%pI4:%d\\n\", &iph->saddr, (iph->protocol == IP_PROTO_TCP) ? tcph->source : udph->source, &iph->daddr, (iph->protocol == IP_PROTO_TCP) ? tcph->dest : udph->dest);\n"
        ebpf_code += "        return TC_ACT_SHOT;\n"
        ebpf_code += "    }\n"
    if filter_default_policy_output == "ACCEPT":
        ebpf_code += "    // Filter OUTPUT chain default policy: ACCEPT\n"
        ebpf_code += "    // OUTPUT chain default ACCEPT is implicit if no other rule matches.\n"


    ebpf_code += """

    return TC_ACT_OK; // Default action if no rule matched (for chains with ACCEPT policy or packets not matching DROP policies)
}

char _license[] SEC("license") = "GPL";
"""
    return ebpf_code

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert iptables JSON to eBPF code (TC).")
    parser.add_argument("-i", "--input", type=argparse.FileType('r'), required=True,
                        help="Path to the input JSON file containing iptables rules.")
    parser.add_argument("-o", "--output", type=str, required=True,
                        help="Path to the output file where TC eBPF code will be written.")

    args = parser.parse_args()

    try:
        iptables_json_data = json.load(args.input)
    except json.JSONDecodeError as e:
        print(f"Error reading JSON file: {e}")
        exit(1)
    except Exception as e:
        print(f"An error occurred while reading the input file: {e}")
        exit(1)

    ebpf_script = json_to_ebpf_script(iptables_json_data)

    try:
        with open(args.output, "w") as outfile:
            outfile.write(ebpf_script)
        print(f"TC eBPF code written to: {args.output}")
    except Exception as e:
        print(f"Error writing to output file: {e}")
        exit(1)