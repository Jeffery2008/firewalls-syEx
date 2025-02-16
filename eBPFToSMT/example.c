#include <linux/bpf.h>

int handle_ingress(void *ctx) {
  // Example eBPF code - simple pass-through
  return 1; 
}
