import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

# Constants
PROJECT_ROOT = Path(__file__).parent.absolute()
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = PROJECT_ROOT / "logs"
OUTPUT_DIR = PROJECT_ROOT / "output"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

# Create necessary directories
CONFIG_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "firewall_tool.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_settings() -> Optional[Dict[str, Any]]:
    """Load settings from the project's config file"""
    try:
        if SETTINGS_FILE.exists():
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return None

def save_settings(settings: Dict[str, Any]) -> bool:
    """Save settings to the project's config file"""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return False

def get_output_path(filename: str) -> Path:
    """Get full path for output file"""
    return OUTPUT_DIR / filename

def get_log_path(name: str = "translation.log") -> Path:
    """Get full path for log file"""
    return LOGS_DIR / name

def initialize_project() -> None:
    """Ensure project structure is properly set up"""
    try:
        # Create example configuration if none exists
        if not SETTINGS_FILE.exists():
            example_settings = {
                "model": "gemini-2.0-flash-thinking-exp-01-21",
                "api_key": "",
                "auto_validate": True,
                "performance_check": True
            }
            save_settings(example_settings)
            
        # Create .gitignore to exclude sensitive files
        gitignore_file = PROJECT_ROOT / ".gitignore"
        if not gitignore_file.exists():
            with open(gitignore_file, 'w', encoding='utf-8') as f:
                f.write("""# Configuration & Logs
/config/settings.json
/logs/
/output/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.env
.venv/

# Build & Distribution
dist/
build/
*.egg-info/
""")
        
        logger.info("Project structure initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing project: {e}")
        raise
