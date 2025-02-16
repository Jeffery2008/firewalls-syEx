; SMT code generated from eBPF using pycparser with preprocessing
(declare-fun pkt_protocol () Int) ; Packet protocol field
(declare-fun pkt_src_ip () Int) ; Packet source IP address field
(declare-fun pkt_dst_ip () Int) ; Packet destination IP address field
(declare-fun pkt_src_port () Int) ; Packet source port field
(declare-fun pkt_dst_port () Int) ; Packet destination port field
(; eBPF code indicates protocol filtering)
(assert (= pkt_protocol 6))
