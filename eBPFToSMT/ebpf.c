```c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <arpa/inet.h>

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline inline __attribute__((always_inline))
#endif

__section("classifier/firewall")
int tc_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned short eth_type;
    unsigned int ip_header_len;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_SHOT;

    eth_type = eth->h_proto;

    if (eth_type == htons(ETH_P_IP)) {
        iph = data + sizeof(*eth);
        if (iph + sizeof(*iph) > data_end)
            return TC_ACT_SHOT;
        ip_header_len = iph->ihl * 4;
        if (iph + ip_header_len > data_end)
            return TC_ACT_SHOT;

        if (iph->protocol == IPPROTO_TCP) {
            tcph = (void *)iph + ip_header_len;
            if (tcph + sizeof(*tcph) > data_end)
                return TC_ACT_SHOT;

            if (tcph->dest == htons(22) || tcph->dest == htons(80) || tcph->dest == htons(443))
                return TC_ACT_OK;
        }
    }

    return TC_ACT_SHOT;
}

char _license[] __section("license") = "GPL";
```