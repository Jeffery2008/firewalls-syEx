#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>

#define ETH_HLEN 14
#define IP_HLEN 20

SEC("tc")
int tc_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_SHOT;

    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK; // Not IP packet, let it pass (or handle other protocols as needed)

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_SHOT;

    // Default DROP policy for INPUT chain (and FORWARD, though FORWARD is less relevant in ingress TC)
    int action = TC_ACT_SHOT;

    // Rule 1: -A INPUT -m state --state INVALID -j DROP
    // Simplified INVALID state check (TCP only, very basic)
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;

        // Very basic invalid state approximation: SYN and RST or SYN and FIN
        if ((tcph->syn && tcph->rst) || (tcph->syn && tcph->fin)) {
            return TC_ACT_SHOT; // DROP INVALID (approximation)
        }
    }


    // Rule 2: -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    // Simplified ESTABLISHED state check (TCP only, basic ACK and no SYN for established)
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;

        if (tcph->ack && !tcph->syn) {
            action = TC_ACT_OK; // ACCEPT ESTABLISHED (approximation) - if it reaches here, it overwrites default DROP initially, and further rules can still override.
            goto rule_evaluation_done; // Skip further checks if ESTABLISHED
        }
    }


    // Rule 3: -A INPUT -i lo -j ACCEPT
    if (skb->ifindex == if_nametoindex("lo")) {
        action = TC_ACT_OK; // ACCEPT loopback
        goto rule_evaluation_done; // Skip further checks
    }

    // Rule 4: -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
        if ((void *)icmph + sizeof(struct icmphdr) > data_end)
            return TC_ACT_SHOT;

        if (icmph->type == ICMP_ECHO) { // ICMP type 8 is ECHO request
            action = TC_ACT_OK; // ACCEPT ICMP echo request
            goto rule_evaluation_done; // Skip further checks
        }
    }

    // Rule 5: -A INPUT -s 195.135.144.144/28 -p tcp -m tcp --dport 22 -j ACCEPT
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;

        if (ntohs(tcph->dest) == 22) { // Destination port 22
            __u32 src_ip = ntohl(iph->saddr);
            __u32 network_ip = 0xC3879090; // 195.135.144.144 in network byte order
            __u32 netmask = 0xFFFFFFF0;    // /28 netmask

            if ((src_ip & netmask) == (network_ip & netmask)) {
                action = TC_ACT_OK; // ACCEPT SSH from 195.135.144.144/28
                goto rule_evaluation_done; // Skip further checks
            }
        }
    }

    // Rule 6: -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;

        if (ntohs(tcph->dest) == 80) { // Destination port 80
            action = TC_ACT_OK; // ACCEPT HTTP
            goto rule_evaluation_done; // Skip further checks
        }
    }

    // Rule 7: -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;

        if (ntohs(tcph->dest) == 443) { // Destination port 443
            action = TC_ACT_OK; // ACCEPT HTTPS
            goto rule_evaluation_done; // Skip further checks
        }
    }

    // Rule 8: -A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        if ((void *)tcph + sizeof(struct tcphdr) > data_end)
            return TC_ACT_SHOT;

        if (ntohs(tcph->dest) == 25) { // Destination port 25
            action = TC_ACT_OK; // ACCEPT SMTP
            goto rule_evaluation_done; // Skip further checks
        }
    }


rule_evaluation_done:
    return action; // Return the determined action (TC_ACT_OK or TC_ACT_SHOT)
}

char _license[] SEC("license") = "GPL";
content_copy
download
Use code with caution.
C