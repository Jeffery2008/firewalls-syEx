#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef USE_KLEE
#include "klee/klee.h"
#endif

#define ACTION_DROP   0
#define ACTION_ACCEPT 1

typedef struct {
    int proto;          // Protocol: -1 = any, 6 = TCP, 17 = UDP, 1 = ICMP
    uint32_t src_ip;
    uint32_t src_mask;  // Added subnet mask
    uint32_t dst_ip;
    uint32_t dst_mask;  // Added subnet mask
    uint16_t src_port;
    uint16_t src_port_high;  // For port ranges
    uint16_t dst_port;
    uint16_t dst_port_high;  // For port ranges
    bool has_state;
    uint8_t state_mask;  // Bitmap for states: NEW=1, ESTABLISHED=2, RELATED=4, INVALID=8
    int action;         // 0 = DROP, 1 = ACCEPT
} ipt_rule_t;

#define MAX_RULES 128
#define STATE_NEW        1
#define STATE_ESTABLISHED 2
#define STATE_RELATED    4
#define STATE_INVALID    8

ipt_rule_t rules[MAX_RULES];
int rules_count = 0;

uint32_t apply_mask(uint32_t ip, uint32_t mask) {
    return ip & mask;
}

void init_rules() {
    // Initialize rules array
    rules[0].proto = -1;
    rules[0].src_ip = 0;
    rules[0].src_mask = 0;
    rules[0].dst_ip = 0;
    rules[0].dst_mask = 0;
    rules[0].src_port = 0;
    rules[0].src_port_high = 0;
    rules[0].dst_port = 0;
    rules[0].dst_port_high = 0;
    rules[0].has_state = false;
    rules[0].state_mask = 0;
    rules[0].action = 1;

    rules[1].proto = -1;
    rules[1].src_ip = 0;
    rules[1].src_mask = 0;
    rules[1].dst_ip = 0;
    rules[1].dst_mask = 0;
    rules[1].src_port = 0;
    rules[1].src_port_high = 0;
    rules[1].dst_port = 0;
    rules[1].dst_port_high = 0;
    rules[1].has_state = true;
    rules[1].state_mask = 6;
    rules[1].action = 1;

    rules[2].proto = -1;
    rules[2].src_ip = 0;
    rules[2].src_mask = 0;
    rules[2].dst_ip = 0;
    rules[2].dst_mask = 0;
    rules[2].src_port = 0;
    rules[2].src_port_high = 0;
    rules[2].dst_port = 0;
    rules[2].dst_port_high = 0;
    rules[2].has_state = true;
    rules[2].state_mask = 8;
    rules[2].action = 0;

    rules[3].proto = 1;
    rules[3].src_ip = 0;
    rules[3].src_mask = 0;
    rules[3].dst_ip = 0;
    rules[3].dst_mask = 0;
    rules[3].src_port = 0;
    rules[3].src_port_high = 0;
    rules[3].dst_port = 0;
    rules[3].dst_port_high = 0;
    rules[3].has_state = false;
    rules[3].state_mask = 0;
    rules[3].action = 1;

    rules[4].proto = 1;
    rules[4].src_ip = 0;
    rules[4].src_mask = 0;
    rules[4].dst_ip = 0;
    rules[4].dst_mask = 0;
    rules[4].src_port = 0;
    rules[4].src_port_high = 0;
    rules[4].dst_port = 0;
    rules[4].dst_port_high = 0;
    rules[4].has_state = false;
    rules[4].state_mask = 0;
    rules[4].action = 1;

    rules[5].proto = 1;
    rules[5].src_ip = 0;
    rules[5].src_mask = 0;
    rules[5].dst_ip = 0;
    rules[5].dst_mask = 0;
    rules[5].src_port = 0;
    rules[5].src_port_high = 0;
    rules[5].dst_port = 0;
    rules[5].dst_port_high = 0;
    rules[5].has_state = false;
    rules[5].state_mask = 0;
    rules[5].action = 1;

    rules[6].proto = 1;
    rules[6].src_ip = 0;
    rules[6].src_mask = 0;
    rules[6].dst_ip = 0;
    rules[6].dst_mask = 0;
    rules[6].src_port = 0;
    rules[6].src_port_high = 0;
    rules[6].dst_port = 0;
    rules[6].dst_port_high = 0;
    rules[6].has_state = false;
    rules[6].state_mask = 0;
    rules[6].action = 1;

    rules[7].proto = 1;
    rules[7].src_ip = 0;
    rules[7].src_mask = 0;
    rules[7].dst_ip = 0;
    rules[7].dst_mask = 0;
    rules[7].src_port = 0;
    rules[7].src_port_high = 0;
    rules[7].dst_port = 0;
    rules[7].dst_port_high = 0;
    rules[7].has_state = false;
    rules[7].state_mask = 0;
    rules[7].action = 1;

    rules[8].proto = 17;
    rules[8].src_ip = 0;
    rules[8].src_mask = 0;
    rules[8].dst_ip = 0;
    rules[8].dst_mask = 0;
    rules[8].src_port = 67;
    rules[8].src_port_high = 67;
    rules[8].dst_port = 68;
    rules[8].dst_port_high = 68;
    rules[8].has_state = false;
    rules[8].state_mask = 0;
    rules[8].action = 1;

    rules[9].proto = -1;
    rules[9].src_ip = 0;
    rules[9].src_mask = 0;
    rules[9].dst_ip = 0;
    rules[9].dst_mask = 0;
    rules[9].src_port = 0;
    rules[9].src_port_high = 0;
    rules[9].dst_port = 0;
    rules[9].dst_port_high = 0;
    rules[9].has_state = false;
    rules[9].state_mask = 0;
    rules[9].action = 0;

    rules[10].proto = 17;
    rules[10].src_ip = 0;
    rules[10].src_mask = 0;
    rules[10].dst_ip = 3758096635;
    rules[10].dst_mask = 4294967295;
    rules[10].src_port = 0;
    rules[10].src_port_high = 0;
    rules[10].dst_port = 5353;
    rules[10].dst_port_high = 5353;
    rules[10].has_state = false;
    rules[10].state_mask = 0;
    rules[10].action = 1;

    rules[11].proto = 17;
    rules[11].src_ip = 0;
    rules[11].src_mask = 0;
    rules[11].dst_ip = 4026531834;
    rules[11].dst_mask = 4294967295;
    rules[11].src_port = 0;
    rules[11].src_port_high = 0;
    rules[11].dst_port = 1900;
    rules[11].dst_port_high = 1900;
    rules[11].has_state = false;
    rules[11].state_mask = 0;
    rules[11].action = 1;

    rules[12].proto = -1;
    rules[12].src_ip = 0;
    rules[12].src_mask = 0;
    rules[12].dst_ip = 0;
    rules[12].dst_mask = 0;
    rules[12].src_port = 0;
    rules[12].src_port_high = 0;
    rules[12].dst_port = 0;
    rules[12].dst_port_high = 0;
    rules[12].has_state = false;
    rules[12].state_mask = 0;
    rules[12].action = 0;

    rules[13].proto = 6;
    rules[13].src_ip = 0;
    rules[13].src_mask = 0;
    rules[13].dst_ip = 0;
    rules[13].dst_mask = 0;
    rules[13].src_port = 0;
    rules[13].src_port_high = 0;
    rules[13].dst_port = 22;
    rules[13].dst_port_high = 22;
    rules[13].has_state = false;
    rules[13].state_mask = 0;
    rules[13].action = 1;

    rules[14].proto = 6;
    rules[14].src_ip = 0;
    rules[14].src_mask = 0;
    rules[14].dst_ip = 0;
    rules[14].dst_mask = 0;
    rules[14].src_port = 0;
    rules[14].src_port_high = 0;
    rules[14].dst_port = 80;
    rules[14].dst_port_high = 80;
    rules[14].has_state = false;
    rules[14].state_mask = 0;
    rules[14].action = 1;

    rules[15].proto = -1;
    rules[15].src_ip = 3160402376;
    rules[15].src_mask = 4294967295;
    rules[15].dst_ip = 0;
    rules[15].dst_mask = 0;
    rules[15].src_port = 0;
    rules[15].src_port_high = 0;
    rules[15].dst_port = 0;
    rules[15].dst_port_high = 0;
    rules[15].has_state = false;
    rules[15].state_mask = 0;
    rules[15].action = 1;

    rules[16].proto = -1;
    rules[16].src_ip = 167772160;
    rules[16].src_mask = 4294967040;
    rules[16].dst_ip = 0;
    rules[16].dst_mask = 0;
    rules[16].src_port = 0;
    rules[16].src_port_high = 0;
    rules[16].dst_port = 0;
    rules[16].dst_port_high = 0;
    rules[16].has_state = false;
    rules[16].state_mask = 0;
    rules[16].action = 1;

    rules[17].proto = 17;
    rules[17].src_ip = 0;
    rules[17].src_mask = 0;
    rules[17].dst_ip = 0;
    rules[17].dst_mask = 0;
    rules[17].src_port = 0;
    rules[17].src_port_high = 0;
    rules[17].dst_port = 0;
    rules[17].dst_port_high = 0;
    rules[17].has_state = false;
    rules[17].state_mask = 0;
    rules[17].action = 1;

    rules[18].proto = 6;
    rules[18].src_ip = 0;
    rules[18].src_mask = 0;
    rules[18].dst_ip = 0;
    rules[18].dst_mask = 0;
    rules[18].src_port = 0;
    rules[18].src_port_high = 0;
    rules[18].dst_port = 8832;
    rules[18].dst_port_high = 8832;
    rules[18].has_state = false;
    rules[18].state_mask = 0;
    rules[18].action = 1;

    rules[19].proto = 6;
    rules[19].src_ip = 0;
    rules[19].src_mask = 0;
    rules[19].dst_ip = 0;
    rules[19].dst_mask = 0;
    rules[19].src_port = 0;
    rules[19].src_port_high = 0;
    rules[19].dst_port = 27562;
    rules[19].dst_port_high = 27562;
    rules[19].has_state = false;
    rules[19].state_mask = 0;
    rules[19].action = 1;

    rules[20].proto = 6;
    rules[20].src_ip = 0;
    rules[20].src_mask = 0;
    rules[20].dst_ip = 0;
    rules[20].dst_mask = 0;
    rules[20].src_port = 0;
    rules[20].src_port_high = 0;
    rules[20].dst_port = 9340;
    rules[20].dst_port_high = 9340;
    rules[20].has_state = false;
    rules[20].state_mask = 0;
    rules[20].action = 1;

    rules[21].proto = 6;
    rules[21].src_ip = 0;
    rules[21].src_mask = 0;
    rules[21].dst_ip = 0;
    rules[21].dst_mask = 0;
    rules[21].src_port = 0;
    rules[21].src_port_high = 0;
    rules[21].dst_port = 9341;
    rules[21].dst_port_high = 9341;
    rules[21].has_state = false;
    rules[21].state_mask = 0;
    rules[21].action = 1;

    rules[22].proto = -1;
    rules[22].src_ip = 3160402218;
    rules[22].src_mask = 4294967295;
    rules[22].dst_ip = 0;
    rules[22].dst_mask = 0;
    rules[22].src_port = 0;
    rules[22].src_port_high = 0;
    rules[22].dst_port = 0;
    rules[22].dst_port_high = 0;
    rules[22].has_state = false;
    rules[22].state_mask = 0;
    rules[22].action = 1;

    rules[23].proto = -1;
    rules[23].src_ip = 0;
    rules[23].src_mask = 0;
    rules[23].dst_ip = 0;
    rules[23].dst_mask = 0;
    rules[23].src_port = 0;
    rules[23].src_port_high = 0;
    rules[23].dst_port = 0;
    rules[23].dst_port_high = 0;
    rules[23].has_state = false;
    rules[23].state_mask = 0;
    rules[23].action = 0;

    rules[24].proto = -1;
    rules[24].src_ip = 0;
    rules[24].src_mask = 0;
    rules[24].dst_ip = 0;
    rules[24].dst_mask = 0;
    rules[24].src_port = 0;
    rules[24].src_port_high = 0;
    rules[24].dst_port = 0;
    rules[24].dst_port_high = 0;
    rules[24].has_state = false;
    rules[24].state_mask = 0;
    rules[24].action = 0;

    rules[25].proto = -1;
    rules[25].src_ip = 0;
    rules[25].src_mask = 0;
    rules[25].dst_ip = 0;
    rules[25].dst_mask = 0;
    rules[25].src_port = 0;
    rules[25].src_port_high = 0;
    rules[25].dst_port = 0;
    rules[25].dst_port_high = 0;
    rules[25].has_state = false;
    rules[25].state_mask = 0;
    rules[25].action = 0;

    rules[26].proto = -1;
    rules[26].src_ip = 0;
    rules[26].src_mask = 0;
    rules[26].dst_ip = 0;
    rules[26].dst_mask = 0;
    rules[26].src_port = 0;
    rules[26].src_port_high = 0;
    rules[26].dst_port = 0;
    rules[26].dst_port_high = 0;
    rules[26].has_state = false;
    rules[26].state_mask = 0;
    rules[26].action = 0;

    rules_count = 27;
}

int check_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, int proto) {
    for (int i = 0; i < rules_count; i++) {
        bool match = true;
        
        // Check protocol
        if (rules[i].proto != -1 && rules[i].proto != proto) {
            match = false;
        }
        
        // Check source IP with mask
        if (rules[i].src_mask != 0 && 
            apply_mask(src_ip, rules[i].src_mask) != apply_mask(rules[i].src_ip, rules[i].src_mask)) {
            match = false;
        }
        
        // Check destination IP with mask
        if (rules[i].dst_mask != 0 && 
            apply_mask(dst_ip, rules[i].dst_mask) != apply_mask(rules[i].dst_ip, rules[i].dst_mask)) {
            match = false;
        }
        
        // Check source port range
        if (rules[i].src_port != 0 && 
            (src_port < rules[i].src_port || src_port > rules[i].src_port_high)) {
            match = false;
        }
        
        // Check destination port range
        if (rules[i].dst_port != 0 && 
            (dst_port < rules[i].dst_port || dst_port > rules[i].dst_port_high)) {
            match = false;
        }

        // Add state checking
        if (rules[i].has_state) {
            uint8_t current_state;
#ifdef USE_KLEE
            klee_make_symbolic(&current_state, sizeof(current_state), "connection_state");
            // Constrain state to valid values (1, 2, 4, or 8)
            klee_assume(current_state == STATE_NEW || 
                       current_state == STATE_ESTABLISHED || 
                       current_state == STATE_RELATED || 
                       current_state == STATE_INVALID);
#else
            current_state = STATE_NEW;  // Default to NEW state for non-KLEE testing
#endif
            if ((rules[i].state_mask & current_state) == 0) {
                match = false;
            }
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
