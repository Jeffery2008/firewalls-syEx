import os
import sys
import pytest
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from firewalls_app import FirewallManager

# Test data directory
TEST_DATA_DIR = PROJECT_ROOT / "tests" / "test_data"
TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

@pytest.fixture
def web_server_rules():
    """Create web server rules for testing."""
    rules = """
    # Allow established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow SSH access
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow HTTP traffic
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    
    # Allow HTTPS traffic
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Drop all other traffic
    iptables -A INPUT -j DROP
    """
    rules_file = TEST_DATA_DIR / "web_server_rules.txt"
    rules_file.write_text(rules)
    return str(rules_file)

@pytest.fixture
def nat_rules():
    """Create NAT rules for testing."""
    rules = """
    # Enable NAT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # Forward port 80 to internal server
    iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:80
    
    # Forward port 443 to internal server
    iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:443
    """
    rules_file = TEST_DATA_DIR / "nat_rules.txt"
    rules_file.write_text(rules)
    return str(rules_file)

@pytest.fixture
def load_balancer_rules():
    """Create load balancer rules for testing."""
    rules = """
    # Forward HTTP traffic to backend servers
    iptables -A PREROUTING -t nat -p tcp --dport 80 -m statistic --mode nth --every 3 --packet 0 -j DNAT --to-destination 10.0.1.101:80
    iptables -A PREROUTING -t nat -p tcp --dport 80 -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 10.0.1.102:80
    iptables -A PREROUTING -t nat -p tcp --dport 80 -j DNAT --to-destination 10.0.1.103:80
    
    # Enable masquerading for outgoing packets
    iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o eth0 -j MASQUERADE
    """
    rules_file = TEST_DATA_DIR / "load_balancer_rules.txt"
    rules_file.write_text(rules)
    return str(rules_file)

@pytest.fixture
def dos_protection_rules():
    """Create DoS protection rules for testing."""
    rules = """
    # Limit new TCP connections to 60 per minute
    iptables -A INPUT -p tcp --syn -m limit --limit 60/m --limit-burst 120 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP
    
    # Limit ICMP ping requests
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    
    # Protect against port scanning
    iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
    iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP
    """
    rules_file = TEST_DATA_DIR / "dos_protection_rules.txt"
    rules_file.write_text(rules)
    return str(rules_file)

@pytest.mark.integration
def test_web_server_rules_translation(web_server_rules):
    """Test translation of web server rules."""
    manager = FirewallManager()
    success, result = manager.process_rules(web_server_rules)
    assert success, f"Web server rules translation failed: {result}"
    
    # Verify output file exists and contains expected eBPF code
    assert Path(result).exists()
    ebpf_code = Path(result).read_text()
    assert "BPF_PROG_TYPE_SOCKET_FILTER" in ebpf_code
    assert "TCP" in ebpf_code
    assert "port" in ebpf_code

@pytest.mark.integration
def test_nat_rules_translation(nat_rules):
    """Test translation of NAT rules."""
    manager = FirewallManager()
    success, result = manager.process_rules(nat_rules)
    assert success, f"NAT rules translation failed: {result}"
    
    # Verify output file exists and contains expected eBPF code
    assert Path(result).exists()
    ebpf_code = Path(result).read_text()
    assert "BPF_PROG_TYPE_NAT" in ebpf_code
    assert "MASQUERADE" in ebpf_code
    assert "DNAT" in ebpf_code

@pytest.mark.integration
def test_load_balancer_rules_translation(load_balancer_rules):
    """Test translation of load balancer rules."""
    manager = FirewallManager()
    success, result = manager.process_rules(load_balancer_rules)
    assert success, f"Load balancer rules translation failed: {result}"
    
    # Verify output file exists and contains expected eBPF code
    assert Path(result).exists()
    ebpf_code = Path(result).read_text()
    assert "BPF_PROG_TYPE_SCHED_CLS" in ebpf_code
    assert "round_robin" in ebpf_code
    assert "backend_servers" in ebpf_code

@pytest.mark.integration
def test_dos_protection_rules_translation(dos_protection_rules):
    """Test translation of DoS protection rules."""
    manager = FirewallManager()
    success, result = manager.process_rules(dos_protection_rules)
    assert success, f"DoS protection rules translation failed: {result}"
    
    # Verify output file exists and contains expected eBPF code
    assert Path(result).exists()
    ebpf_code = Path(result).read_text()
    assert "BPF_PROG_TYPE_XDP" in ebpf_code
    assert "rate_limit" in ebpf_code
    assert "syn_flood" in ebpf_code

@pytest.mark.integration
def test_rule_verification_consistency(web_server_rules):
    """Test that translated rules are verified as consistent."""
    manager = FirewallManager()
    
    # First run without verification
    success, ebpf_file = manager.process_rules(web_server_rules, skip_verify=True)
    assert success, "Translation failed"
    
    # Then verify the rules
    success, result = manager.process_rules(web_server_rules)
    assert success, f"Verification failed: {result}"

@pytest.mark.integration
def test_invalid_rules_handling():
    """Test handling of invalid iptables rules."""
    # Create invalid rules
    invalid_rules = """
    # Invalid rule with wrong syntax
    iptables --invalid-option
    
    # Invalid rule with non-existent chain
    iptables -A NONEXISTENT -j ACCEPT
    """
    rules_file = TEST_DATA_DIR / "invalid_rules.txt"
    rules_file.write_text(invalid_rules)
    
    manager = FirewallManager()
    success, message = manager.process_rules(str(rules_file))
    assert not success
    assert "validation failed" in message.lower()

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-m', 'integration'])
