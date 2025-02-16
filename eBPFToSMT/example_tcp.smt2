; SMT code generated from eBPF for protocol filtering
(declare-fun pkt_protocol () Int) ; Packet protocol field
(; eBPF code indicates TCP filtering)
(assert (= pkt_protocol 6)) ; TCP protocol number is 6
