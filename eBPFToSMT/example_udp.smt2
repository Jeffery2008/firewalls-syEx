; SMT code generated from eBPF for protocol filtering
(declare-fun pkt_protocol () Int) ; Packet protocol field
(; eBPF code indicates UDP filtering)
(assert (= pkt_protocol 17)) ; UDP protocol number is 17
