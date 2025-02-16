import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from ebpf_templates import build_base_program, generate_match_conditions

class TestEBPFTemplates(unittest.TestCase):
    def test_base_program_generation(self):
        # Test with no protocols
        base_code = build_base_program()
        self.assertIn('SEC("classifier")', base_code)
        self.assertIn('struct ethhdr *eth = data;', base_code)
        
        # Test with specific protocols
        protocols = {'tcp', 'udp', 'ip'}
        code_with_protos = build_base_program(protocols)
        self.assertIn('struct tcphdr *tcph', code_with_protos)
        self.assertIn('struct udphdr *udph', code_with_protos)
        self.assertIn('struct iphdr *iph', code_with_protos)
        
        # Test with conntrack
        code_with_ct = build_base_program(use_conntrack=True)
        self.assertIn('bpf_skb_ct_state_get', code_with_ct)
        
        # Test with both
        full_code = build_base_program({'tcp', 'ip'}, True)
        self.assertIn('struct tcphdr *tcph', full_code)
        self.assertIn('bpf_skb_ct_state_get', full_code)
    
    def test_match_condition_generation(self):
        # Test with various match conditions
        matches = {
            'src_ip': '0x0A000001',  # 10.0.0.1
            'dst_port': '80',
            'proto': 'tcp'
        }
        conditions = generate_match_conditions(matches)
        self.assertIn('if (iph->saddr == 0x0A000001)', conditions)
        self.assertIn('if (bpf_ntohs(tcph->dest) == 80)', conditions)
        self.assertIn('if (iph->protocol == IPPROTO_TCP)', conditions)
        
        # Test empty matches
        empty_conditions = generate_match_conditions({})
        self.assertEqual(empty_conditions, '')

if __name__ == '__main__':
    unittest.main()
