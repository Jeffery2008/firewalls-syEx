; SMT code generated from eBPF for protocol and IP filtering
(declare-fun pkt_protocol () Int) ; Packet protocol field
(declare-fun pkt_src_ip () Int) ; Packet source IP address field
(declare-fun pkt_dst_ip () Int) ; Packet destination IP address field
(; eBPF code does not indicate specific protocol filtering - pass all protocols)
(assert true) ; Pass all protocols
(; eBPF code indicates destination IP filtering: 10.0.0.5)
(assert (= pkt_dst_ip 167772165))
