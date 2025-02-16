import os
import sys
import json
import pytest
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))

from firewalls_app import FirewallManager

# Test data directory
TEST_DATA_DIR = PROJECT_ROOT / "tests" / "test_data"
TEST_DATA_DIR.mkdir(parents=True, exist_ok=True)

@pytest.fixture
def sample_rules():
    """Create sample iptables rules for testing."""
    rules = """
    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow HTTP
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    
    # Drop everything else
    iptables -A INPUT -j DROP
    """
    rules_file = TEST_DATA_DIR / "sample_rules.txt"
    rules_file.write_text(rules)
    return str(rules_file)

@pytest.fixture
def config_file():
    """Create a sample configuration file."""
    config = {
        "model": "test-model",
        "auto_validate": True,
        "gemini_api_key": "test-key"
    }
    config_file = TEST_DATA_DIR / "test_config.json"
    with open(config_file, 'w') as f:
        json.dump(config, f)
    return str(config_file)

@pytest.fixture
def manager(config_file):
    """Create a FirewallManager instance with test configuration."""
    return FirewallManager(config_file)

def test_load_config_with_file(manager, config_file):
    """Test loading configuration from file."""
    assert manager.config["model"] == "test-model"
    assert manager.config["auto_validate"] is True
    assert manager.config["gemini_api_key"] == "test-key"

def test_load_config_defaults():
    """Test loading default configuration."""
    manager = FirewallManager()
    assert manager.config["model"] == "gemini-2.0-flash-thinking-exp-01-21"
    assert manager.config["auto_validate"] is True

@patch('firewalls_app.validate_iptables_rules')
def test_process_rules_validation_failure(mock_validate, manager, sample_rules):
    """Test handling of validation failures."""
    mock_validate.return_value = False
    success, message = manager.process_rules(sample_rules)
    assert not success
    assert message == "Input validation failed"

@patch('firewalls_app.validate_iptables_rules')
@patch('firewalls_app.EBPFTranslator')
def test_process_rules_translation_failure(mock_translator, mock_validate, manager, sample_rules):
    """Test handling of translation failures."""
    mock_validate.return_value = True
    mock_translator.return_value.translate_rules.return_value = None
    success, message = manager.process_rules(sample_rules)
    assert not success
    assert "Translation failed" in message

@patch('firewalls_app.validate_iptables_rules')
@patch('firewalls_app.EBPFTranslator')
@patch('firewalls_app.process_firewall')
@patch('firewalls_app.check_consistency')
def test_process_rules_success(mock_check, mock_process, mock_translator, mock_validate, 
                             manager, sample_rules, tmp_path):
    """Test successful rule processing."""
    # Setup mocks
    mock_validate.return_value = True
    ebpf_file = tmp_path / "output.ebpf"
    ebpf_file.write_text("// eBPF code")
    mock_translator.return_value.translate_rules.return_value = str(ebpf_file)
    mock_process.return_value = True
    mock_check.return_value = (True, "Success")
    
    # Run test
    success, result = manager.process_rules(sample_rules)
    assert success
    assert "output.ebpf" in result

@patch('firewalls_app.validate_iptables_rules')
@patch('firewalls_app.EBPFTranslator')
@patch('firewalls_app.process_firewall')
@patch('firewalls_app.check_consistency')
def test_process_rules_verification_failure(mock_check, mock_process, mock_translator, 
                                         mock_validate, manager, sample_rules, tmp_path):
    """Test handling of verification failures."""
    # Setup mocks
    mock_validate.return_value = True
    ebpf_file = tmp_path / "output.ebpf"
    ebpf_file.write_text("// eBPF code")
    mock_translator.return_value.translate_rules.return_value = str(ebpf_file)
    mock_process.return_value = True
    mock_check.return_value = (False, "Verification failed")
    
    # Run test
    success, message = manager.process_rules(sample_rules)
    assert not success
    assert "Verification failed" in message

def test_process_rules_skip_verify(manager, sample_rules, tmp_path):
    """Test skipping verification step."""
    with patch('firewalls_app.validate_iptables_rules') as mock_validate, \
         patch('firewalls_app.EBPFTranslator') as mock_translator:
        
        # Setup mocks
        mock_validate.return_value = True
        ebpf_file = tmp_path / "output.ebpf"
        ebpf_file.write_text("// eBPF code")
        mock_translator.return_value.translate_rules.return_value = str(ebpf_file)
        
        # Run test
        success, result = manager.process_rules(sample_rules, skip_verify=True)
        assert success
        assert "output.ebpf" in result

def test_output_directory_creation(tmp_path):
    """Test output directory is created if it doesn't exist."""
    with patch('firewalls_app.PROJECT_ROOT', tmp_path):
        manager = FirewallManager()
        assert (tmp_path / "output").exists()

def test_log_directory_creation(tmp_path):
    """Test log directory is created if it doesn't exist."""
    with patch('firewalls_app.PROJECT_ROOT', tmp_path):
        import firewalls_app  # This will trigger directory creation
        assert (tmp_path / "logs").exists()

def test_config_directory_creation(tmp_path):
    """Test config directory is created if it doesn't exist."""
    with patch('firewalls_app.PROJECT_ROOT', tmp_path):
        manager = FirewallManager()
        assert (tmp_path / "config").exists()

@patch('firewalls_app.tk.Tk')
@patch('firewalls_app.FirewallToolGUI')
def test_start_gui(mock_gui, mock_tk, manager):
    """Test GUI initialization."""
    manager.start_gui()
    assert mock_gui.called
    assert mock_tk.return_value.mainloop.called

def test_main_help(capsys):
    """Test main function help output."""
    with pytest.raises(SystemExit):
        with patch('sys.argv', ['firewalls_app.py']):
            import firewalls_app
            firewalls_app.main()
    
    captured = capsys.readouterr()
    assert "IPTables to eBPF Translation Tool" in captured.out

if __name__ == '__main__':
    pytest.main([__file__])
