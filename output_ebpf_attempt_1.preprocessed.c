//#include <uapi/linux/ptrace.h> // Commented out to try to fix compilation error
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <linux/netdevice.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <arpa/inet.h> // For ntohs, etc.

#define DROP TC_ACT_SHOT
#define ACCEPT TC_ACT_OK

/*
 *  eBPF program to implement the iptables rules.
 *  This program is designed to be attached to the TC ingress hook.
 */

BPF_PROG(iptables_filter, struct sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) {
        return ACCEPT; // Malformed packet, let kernel handle it, or DROP if you want strictness
    }

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)iph + sizeof(*iph) > data_end) {
            return ACCEPT; // Malformed IP header, let kernel handle it
        }

        // --state INVALID, RELATED, ESTABLISHED are complex and require connection tracking.
        // eBPF has limited direct access to conntrack state in a performant way for TC filters.
        // For simplicity and direct translation of *these specific rules*, we'll skip stateful inspection.
        // In a real-world scenario needing stateful firewall, you might need more advanced eBPF techniques
        // or consider other approaches.

        // -A INPUT -i lo -j ACCEPT
        int ifindex = skb->dev->ifindex;
        if (ifindex == if_nametoindex("lo")) {
            return ACCEPT;
        }


        if (iph->protocol == IPPROTO_ICMP) {
            // -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
            struct icmphdr *icmph = (struct icmphdr *)(iph + 1);
            if ((void *)icmph + sizeof(*icmph) > data_end) {
                return ACCEPT; // Malformed ICMP header
            }
            if (icmph->type == ICMP_ECHO) { // ICMP type 8 is ECHO request
                return ACCEPT;
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            if ((void *)tcph + sizeof(*tcph) > data_end) {
                return ACCEPT; // Malformed TCP header
            }
            __be16 dest_port = tcph->dest;

            // -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
            if (dest_port == htons(22)) {
                return ACCEPT;
            }

            // -A INPUT -p tcp -m tcp --dport 113 -j ACCEPT
            if (dest_port == htons(113)) {
                return ACCEPT;
            }
        }
    }

    // Default policy: :INPUT DROP
    return DROP;
}

char _license[] SEC("license") = "GPL";
