#include <linux/bpf.h>

int handle_ingress(void *ctx) {
  // Example eBPF code - filter by source IP
  // source IP: 192.168.1.100
  if (packet_src_ip(ctx) == 0xC0A80164) { // 192.168.1.100 in int
    return 1; // Pass packets from 192.168.1.100
  }
  return 0; // Drop other packets
}
