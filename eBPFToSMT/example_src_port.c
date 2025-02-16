#include <linux/bpf.h>

int handle_ingress(void *ctx) {
  // Example eBPF code - filter by source port
  // source port: 8080
  if (packet_src_port(ctx) == 8080) { 
    return 1; // Pass packets from source port 8080
  }
  return 0; // Drop other packets
}
