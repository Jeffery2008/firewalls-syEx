#include <linux/bpf.h>

int handle_ingress(void *ctx) {
  // Example eBPF code - filter by destination port
  // destination port: 22
  if (packet_dst_port(ctx) == 22) { 
    return 1; // Pass packets to destination port 22 (SSH)
  }
  return 0; // Drop other packets
}
