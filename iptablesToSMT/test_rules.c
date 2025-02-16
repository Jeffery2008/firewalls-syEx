#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef USE_KLEE
#include "klee/klee.h"
#endif

#define ACTION_DROP   0
#define ACTION_ACCEPT 1

typedef struct {
    int proto;  // Protocol: -1 = any, 6 = TCP, 17 = UDP, 1 = ICMP
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int action; // 0 = DROP, 1 = ACCEPT
} ipt_rule_t;

#define MAX_RULES 128

ipt_rule_t rules[MAX_RULES];
int rules_count = 0;

void init_rules() {
    // Initialize rules array
    rules[0].proto = 6;
    rules[0].src_ip = 0;
    rules[0].dst_ip = 0;
    rules[0].src_port = 0;
    rules[0].dst_port = 22;
    rules[0].action = 1;

    rules[1].proto = 6;
    rules[1].src_ip = 0;
    rules[1].dst_ip = 0;
    rules[1].src_port = 0;
    rules[1].dst_port = 80;
    rules[1].action = 1;

    rules[2].proto = 6;
    rules[2].src_ip = 0;
    rules[2].dst_ip = 0;
    rules[2].src_port = 0;
    rules[2].dst_port = 443;
    rules[2].action = 1;

    rules[3].proto = 6;
    rules[3].src_ip = 0;
    rules[3].dst_ip = 0;
    rules[3].src_port = 0;
    rules[3].dst_port = 30033;
    rules[3].action = 1;

    rules[4].proto = 17;
    rules[4].src_ip = 0;
    rules[4].dst_ip = 0;
    rules[4].src_port = 0;
    rules[4].dst_port = 9987;
    rules[4].action = 1;

    rules[5].proto = 6;
    rules[5].src_ip = 0;
    rules[5].dst_ip = 0;
    rules[5].src_port = 0;
    rules[5].dst_port = 13001;
    rules[5].action = 1;

    rules[6].proto = 6;
    rules[6].src_ip = 0;
    rules[6].dst_ip = 0;
    rules[6].src_port = 0;
    rules[6].dst_port = 13001;
    rules[6].action = 1;

    rules[7].proto = -1;
    rules[7].src_ip = 0;
    rules[7].dst_ip = 0;
    rules[7].src_port = 0;
    rules[7].dst_port = 0;
    rules[7].action = 0;

    rules[8].proto = -1;
    rules[8].src_ip = 0;
    rules[8].dst_ip = 0;
    rules[8].src_port = 0;
    rules[8].dst_port = 0;
    rules[8].action = 1;

    rules[9].proto = -1;
    rules[9].src_ip = 0;
    rules[9].dst_ip = 0;
    rules[9].src_port = 0;
    rules[9].dst_port = 0;
    rules[9].action = 1;

    rules[10].proto = -1;
    rules[10].src_ip = 0;
    rules[10].dst_ip = 0;
    rules[10].src_port = 0;
    rules[10].dst_port = 0;
    rules[10].action = 1;

    rules[11].proto = 6;
    rules[11].src_ip = 0;
    rules[11].dst_ip = 0;
    rules[11].src_port = 0;
    rules[11].dst_port = 8080;
    rules[11].action = 1;

    rules[12].proto = -1;
    rules[12].src_ip = 3573669274;
    rules[12].dst_ip = 0;
    rules[12].src_port = 0;
    rules[12].dst_port = 0;
    rules[12].action = 1;

    rules[13].proto = 17;
    rules[13].src_ip = 0;
    rules[13].dst_ip = 2886795265;
    rules[13].src_port = 0;
    rules[13].dst_port = 4500;
    rules[13].action = 1;

    rules[14].proto = 17;
    rules[14].src_ip = 0;
    rules[14].dst_ip = 2886795265;
    rules[14].src_port = 0;
    rules[14].dst_port = 500;
    rules[14].action = 1;

    rules[15].proto = -1;
    rules[15].src_ip = 0;
    rules[15].dst_ip = 0;
    rules[15].src_port = 0;
    rules[15].dst_port = 0;
    rules[15].action = 0;

    rules[16].proto = -1;
    rules[16].src_ip = 0;
    rules[16].dst_ip = 0;
    rules[16].src_port = 0;
    rules[16].dst_port = 0;
    rules[16].action = 0;

    rules_count = 17;
}

int check_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, int proto) {
    for (int i = 0; i < rules_count; i++) {
        bool match = true;
        
        // Check protocol
        if (rules[i].proto != -1 && rules[i].proto != proto) {
            match = false;
        }
        
        // Check source IP
        if (rules[i].src_ip != 0 && rules[i].src_ip != src_ip) {
            match = false;
        }
        
        // Check destination IP
        if (rules[i].dst_ip != 0 && rules[i].dst_ip != dst_ip) {
            match = false;
        }
        
        // Check source port
        if (rules[i].src_port != 0 && rules[i].src_port != src_port) {
            match = false;
        }
        
        // Check destination port
        if (rules[i].dst_port != 0 && rules[i].dst_port != dst_port) {
            match = false;
        }
        
        if (match) {
            return rules[i].action;
        }
    }
    
    return ACTION_DROP;  // Default policy
}

#ifndef CONCRETE_TEST
int main() {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    int proto;
    
#ifdef USE_KLEE
    klee_make_symbolic(&src_ip, sizeof(src_ip), "src_ip");
    klee_make_symbolic(&dst_ip, sizeof(dst_ip), "dst_ip");
    klee_make_symbolic(&src_port, sizeof(src_port), "src_port");
    klee_make_symbolic(&dst_port, sizeof(dst_port), "dst_port");
    klee_make_symbolic(&proto, sizeof(proto), "proto");
#else
    // Default test values when not using KLEE
    src_ip = 3232235876;  // 192.168.1.100
    dst_ip = 0;
    src_port = 1024;
    dst_port = 80;
    proto = 6;  // TCP
#endif

    init_rules();
    int result = check_packet(src_ip, dst_ip, src_port, dst_port, proto);
    
#ifdef USE_KLEE
    if (result == ACTION_ACCEPT) {
        klee_warning("ACCEPT");
        klee_assert(result == ACTION_ACCEPT);
    } else {
        klee_warning("DROP");
        klee_assert(result == ACTION_DROP);
    }
#endif
    return result;
}
#endif
