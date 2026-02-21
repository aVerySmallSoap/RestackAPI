"""
Configuration loader with cross-platform path support.
"""
import json
import os
from pathlib import Path

# Get the project root directory (where main.py is)
PROJECT_ROOT = Path(__file__).parent.parent.parent.absolute()

def normalize_path(path_str):
    """Convert paths to be OS-appropriate and absolute."""
    if not path_str:
        return path_str
    
    # Expand ~ to home directory
    path_str = os.path.expanduser(path_str)
    
    # If it's already absolute, return it
    if os.path.isabs(path_str):
        return str(Path(path_str))
    
    # If relative, make it absolute from PROJECT_ROOT
    return str(PROJECT_ROOT / path_str)

def ensure_dir_exists(path):
    """Create directory if it doesn't exist."""
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

def load_config(config_path="config/sample_env.json"):
    """Load configuration and normalize all paths."""
    config_file = PROJECT_ROOT / config_path
    
    with open(config_file, "r") as f:
        config = json.load(f)
    
    # Normalize template paths
    if "templates_path" in config:
        for key, value in config["templates_path"].items():
            if value:
                config["templates_path"][key] = normalize_path(value)
    
    # Normalize and create report paths
    if "report_paths" in config:
        for key, value in config["report_paths"].items():
            if value:
                normalized = normalize_path(value)
                config["report_paths"][key] = normalized
                ensure_dir_exists(normalized)
    
    return config

DEV_ENV = load_config(config_path="config/ENV.json")