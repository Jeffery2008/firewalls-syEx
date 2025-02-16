#include <linux/bpf.h>

int handle_ingress(void *ctx) {
  // Example eBPF code - filter by destination IP
  // destination IP: 10.0.0.5
  if (packet_dst_ip(ctx) == 0x0A000005) { // 10.0.0.5 in int
    return 1; // Pass packets to 10.0.0.5
  }
  return 0; // Drop other packets
}
