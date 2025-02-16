; SMT code generated from eBPF for protocol, IP and port filtering
(declare-fun pkt_protocol () Int) ; Packet protocol field
(declare-fun pkt_src_ip () Int) ; Packet source IP address field
(declare-fun pkt_dst_ip () Int) ; Packet destination IP address field
(declare-fun pkt_src_port () Int) ; Packet source port field
(declare-fun pkt_dst_port () Int) ; Packet destination port field
(; eBPF code does not indicate specific protocol filtering - pass all protocols)
(assert true) ; Pass all protocols
(; eBPF code indicates destination port filtering: 22)
(assert (= pkt_dst_port 22))
