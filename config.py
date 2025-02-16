from pathlib import Path
import json

CONFIG_FILE = Path("config.json")

DEFAULT_CONFIG = {
    "gemini_api_key": "AIzaSyA979FQXSOj27Fe7Y7akNnxVbKgkehHYxc",
    "gemini_model": "gemini-2.0-flash-thinking-exp-01-21",
    "temperature": 0.2,  # Lower temperature for more deterministic output
    "max_output_tokens": 8192,  # Increased token limit for complex eBPF code
    "top_k": 1,  # More focused sampling
    "top_p": 0.8,  # More precise token selection
}

def load_config():
    """Load configuration from file or create default if not exists."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return DEFAULT_CONFIG.copy()

def save_config(config):
    """Save configuration to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def update_config(api_key=None, model=None, temperature=None, max_tokens=None):
    """Update configuration with new values."""
    config = load_config()
    
    if api_key is not None:
        config["gemini_api_key"] = api_key
    if model is not None:
        config["gemini_model"] = model
    if temperature is not None:
        config["temperature"] = temperature
    if max_tokens is not None:
        config["max_output_tokens"] = max_tokens
        
    save_config(config)
    return config
