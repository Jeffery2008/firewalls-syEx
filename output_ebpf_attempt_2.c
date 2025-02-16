```c
#include <uapi/linux/bpf.h>
#include <linux/pkt_cls.h>
#include <net/inet_common.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/in.h>

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...) __attribute__((section("classifier"))), __attribute__((always_inline)) int NAME(__VA_ARGS__)
#endif

#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define ETH_HLEN sizeof(struct ethhdr)
#define IP_HLEN sizeof(struct iphdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)

BPF_FUNC(tc_filter, struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __be16 eth_type;
    __be16 protocol;
    unsigned int pkt_len = data_end - data;

    if (pkt_len < ETH_HLEN)
        return TC_ACT_SHOT;

    eth_type = eth->h_proto;

    if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
        eth = (struct ethhdr *)((void *)eth + 4); // Skip VLAN tag
        if ((void *)eth + ETH_HLEN > data_end)
            return TC_ACT_SHOT;
        eth_type = eth->h_proto;
    }

    if (eth_type != htons(ETH_P_IP))
        return TC_ACT_OK; // Allow non-IP traffic

    iph = (struct iphdr *)((void *)eth + ETH_HLEN);
    if ((void *)iph + IP_HLEN > data_end)
        return TC_ACT_SHOT;

    protocol = iph->protocol;

    if (protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((void *)iph + IP_HLEN);
        if ((void *)tcph + TCP_HLEN > data_end)
            return TC_ACT_SHOT;

        __be16 dest_port = tcph->dest;

        if (dest_port == htons(22) || dest_port == htons(80) || dest_port == htons(443))
            return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
```