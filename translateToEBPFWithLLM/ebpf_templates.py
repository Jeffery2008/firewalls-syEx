"""eBPF code templates and common structures for TC programs."""

# Base template with required headers and sections
BASE_TEMPLATE = '''
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* TC classifier section */
SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    /* Packet parsing */
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;
        
    /* Default: pass packet */
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
'''

# Common protocol header parsing blocks
PARSE_IP_HEADER = '''
    struct iphdr *iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return TC_ACT_OK;
'''

PARSE_TCP_HEADER = '''
    struct tcphdr *tcph = (void*)(iph + 1);
    if ((void*)(tcph + 1) > data_end)
        return TC_ACT_OK;
'''

PARSE_UDP_HEADER = '''
    struct udphdr *udph = (void*)(iph + 1);
    if ((void*)(udph + 1) > data_end)
        return TC_ACT_OK;
'''

PARSE_ICMP_HEADER = '''
    struct icmphdr *icmph = (void*)(iph + 1);
    if ((void*)(icmph + 1) > data_end)
        return TC_ACT_OK;
'''

# Connection tracking helper
CONNTRACK_HELPERS = '''
static __always_inline int check_ct_state(struct __sk_buff *skb)
{
    struct bpf_ct_opts opts = {};
    opts.l4proto = IPPROTO_TCP;
    opts.netns_id = skb->cb[0];
    return bpf_skb_ct_state_get(skb, &opts);
}
'''

def get_protocol_parsing(protocol: str) -> str:
    """Get header parsing code for specific protocol."""
    parsers = {
        'ip': PARSE_IP_HEADER,
        'tcp': PARSE_TCP_HEADER,
        'udp': PARSE_UDP_HEADER,
        'icmp': PARSE_ICMP_HEADER
    }
    return parsers.get(protocol.lower(), '')

def build_base_program(protocols: set[str] = None, use_conntrack: bool = False) -> str:
    """Build base eBPF program with specified protocols and optional conntrack."""
    code = BASE_TEMPLATE
    
    # Add protocol parsing
    if protocols:
        code = code.replace('    return TC_ACT_OK;', '')
        for protocol in protocols:
            code += get_protocol_parsing(protocol)
            
    # Add conntrack if needed
    if use_conntrack:
        # Add helper function before main function
        insert_point = code.find('SEC("classifier")')
        code = code[:insert_point] + CONNTRACK_HELPERS + code[insert_point:]
        
    return code

def analyze_iptables_rules(rules_text: str) -> tuple[set[str], bool, dict]:
    """Analyze iptables rules to determine required protocols and features.
    
    Returns:
        tuple: (set of protocols, bool for conntrack usage, dict of common matches)
    """
    protocols = set()
    use_conntrack = False
    common_matches = {}
    
    # Lowercase for case-insensitive matching
    rules_lower = rules_text.lower()
    
    # Protocol detection patterns
    proto_patterns = {
        'tcp': ['-p tcp', 'tcp ', '--tcp-flags', '--sport', '--dport'],
        'udp': ['-p udp', 'udp ', '--sport', '--dport'],
        'icmp': ['-p icmp', 'icmp ', '--icmp-type']
    }
    
    for proto, patterns in proto_patterns.items():
        if any(p in rules_lower for p in patterns):
            protocols.add(proto)
    
    # Always include IP parsing for network layer
    protocols.add('ip')
    
    # Connection tracking detection
    ct_patterns = [
        '-m state', '--state', 
        'ESTABLISHED', 'RELATED', 'NEW', 'INVALID',
        '-m conntrack', '--ctstate'
    ]
    for pattern in ct_patterns:
        if pattern.lower() in rules_lower:
            use_conntrack = True
            break
    
    return protocols, use_conntrack, common_matches

def generate_match_conditions(matches: dict) -> str:
    """Generate matching conditions for various criteria."""
    conditions = []
    
    # IP address matches
    if 'src_ip' in matches:
        conditions.append(f'    if (iph->saddr == {matches["src_ip"]})')
    if 'dst_ip' in matches:
        conditions.append(f'    if (iph->daddr == {matches["dst_ip"]})')
    
    # Port matches (only if TCP/UDP)
    if any(k in matches for k in ['src_port', 'dst_port']):
        conditions.append('    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {')
        if 'src_port' in matches:
            conditions.append(f'        if (bpf_ntohs(tcph->source) == {matches["src_port"]})')
        if 'dst_port' in matches:
            conditions.append(f'        if (bpf_ntohs(tcph->dest) == {matches["dst_port"]})')
        conditions.append('    }')
    
    # Protocol matches
    if 'proto' in matches:
        conditions.append(f'    if (iph->protocol == IPPROTO_{matches["proto"].upper()})')
    
    # ICMP type matches
    if 'icmp_type' in matches:
        conditions.append('    if (iph->protocol == IPPROTO_ICMP) {')
        conditions.append(f'        if (icmph->type == {matches["icmp_type"]})')
        conditions.append('    }')
    
    return '\n'.join(conditions)
