#!/usr/bin/env python3
"""
RestackAPI Directory Setup Script
Creates all necessary directories for the security scanning application.
Works on Windows, Linux, and macOS.
"""

import json
import os
import sys
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color
    
    @classmethod
    def disable(cls):
        """Disable colors (for Windows or when not supported)"""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = cls.NC = ''


# Disable colors on Windows if not using a compatible terminal
if sys.platform == 'win32' and not os.environ.get('ANSICON'):
    Colors.disable()


def print_info(message):
    """Print info message"""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")


def print_success(message):
    """Print success message"""
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {message}")


def print_warning(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")


def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")


def create_directory(dir_path: Path, description: str) -> bool:
    """
    Create directory with error handling
    
    Args:
        dir_path: Path object for the directory to create
        description: Human-readable description of the directory
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if dir_path.exists():
            print_warning(f"Directory already exists: {dir_path}")
            return True
        else:
            dir_path.mkdir(parents=True, exist_ok=True)
            print_success(f"Created {description}: {dir_path}")
            return True
    except Exception as e:
        print_error(f"Failed to create {description}: {dir_path}")
        print_error(f"Error: {e}")
        return False


def get_base_directory() -> Path:
    """
    Get base directory for installation with user input
    
    Returns:
        Path object for the base directory
    """
    default_base = Path.home() / "RestackAPI"
    
    print_info(f"Default installation directory: {default_base}")
    user_input = input(f"Press Enter to use default, or enter custom path: ").strip()
    
    if user_input:
        return Path(user_input).expanduser().resolve()
    return default_base


def create_directory_structure(base_dir: Path) -> bool:
    """
    Create all necessary directories
    
    Args:
        base_dir: Base directory path
        
    Returns:
        True if all directories created successfully
    """
    directories = {
        # Report directories
        base_dir / "reports" / "wapiti": "Wapiti reports",
        base_dir / "reports" / "full_scan": "Full scan reports",
        
        # Temporary directories
        base_dir / "temp" / "whatweb": "WhatWeb temp",
        base_dir / "temp" / "zap": "ZAP temp",
        base_dir / "temp" / "search_vulns": "SearchVulns temp",
        
        # Discovery directories
        base_dir / "tmp" / "discovery" / "subfinder": "Subfinder discovery",
        
        # Vulnerability scan directories
        base_dir / "tmp" / "vulnerabilities" / "nuclei": "Nuclei vulnerabilities",
    }
    
    success = True
    
    # Create base directory first
    print_info("Creating base directory...")
    if not create_directory(base_dir, "Base directory"):
        return False
    
    # Create report directories
    print()
    print_info("Creating report directories...")
    for path, desc in [(p, d) for p, d in directories.items() if "report" in str(p)]:
        if not create_directory(path, desc):
            success = False
    
    # Create temporary directories
    print()
    print_info("Creating temporary directories...")
    for path, desc in [(p, d) for p, d in directories.items() if "temp" in str(p)]:
        if not create_directory(path, desc):
            success = False
    
    # Create discovery directories
    print()
    print_info("Creating discovery directories...")
    for path, desc in [(p, d) for p, d in directories.items() if "discovery" in str(p)]:
        if not create_directory(path, desc):
            success = False
    
    # Create vulnerability scan directories
    print()
    print_info("Creating vulnerability scan directories...")
    for path, desc in [(p, d) for p, d in directories.items() if "vulnerabilities" in str(p)]:
        if not create_directory(path, desc):
            success = False
    
    return success


def generate_config_file(base_dir: Path):
    """
    Generate config/ENV.json from example if it doesn't exist
    
    Args:
        base_dir: Base directory path
    """
    config_file = Path("config") / "ENV.json"
    example_file = Path("config") / "ENV.example.json"
    
    if config_file.exists():
        print_warning(f"{config_file} already exists. Skipping config generation.")
        return
    
    print()
    print_info("Generating ENV.json from example...")
    
    if not example_file.exists():
        print_error(f"{example_file} not found. Cannot generate config.")
        return
    
    try:
        # Create config directory if it doesn't exist
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Use forward slashes for cross-platform compatibility in JSON
        base_str = str(base_dir).replace('\\', '/')
        
        config = {
            "templates_path": {
                "wapiti": "config/templates/wapiti_config.json",
                "active_scans": "config/templates/active_scan.json",
                "whatweb": "",
                "zap": ""
            },
            "report_paths": {
                "wapiti": f"{base_str}/reports/wapiti",
                "whatweb": f"{base_str}/temp/whatweb",
                "zap": f"{base_str}/temp/zap",
                "searchVulns": f"{base_str}/temp/search_vulns",
                "full_scan": f"{base_str}/reports/full_scan",
                "subfinder": f"{base_str}/tmp/discovery/subfinder",
                "nuclei": f"{base_str}/tmp/vulnerabilities/nuclei"
            },
            "api_keys": {
                "gemini": "YOUR_API_KEY_HERE"
            }
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        
        print_success(f"Created {config_file}")
        print_warning(f"Remember to update API keys in {config_file}")
        
    except Exception as e:
        print_error(f"Failed to generate config file: {e}")


def print_directory_tree(base_dir: Path, prefix: str = "", max_depth: int = 3, current_depth: int = 0):
    """
    Print directory tree structure
    
    Args:
        base_dir: Base directory to print
        prefix: Prefix for tree lines
        max_depth: Maximum depth to traverse
        current_depth: Current depth level
    """
    if current_depth >= max_depth:
        return
    
    try:
        items = sorted(base_dir.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        
        for i, item in enumerate(items):
            is_last = i == len(items) - 1
            current_prefix = "└── " if is_last else "├── "
            print(f"{prefix}{current_prefix}{item.name}")
            
            if item.is_dir():
                extension = "    " if is_last else "│   "
                print_directory_tree(item, prefix + extension, max_depth, current_depth + 1)
    except PermissionError:
        pass


def main():
    """Main setup function"""
    print()
    print("RestackAPI Directory Setup")
    print("==========================")
    print()
    
    # Get base directory
    base_dir = get_base_directory()
    print()
    print_info(f"Installation directory: {base_dir}")
    print()
    
    # Create directory structure
    success = create_directory_structure(base_dir)
    
    if success:
        print()
        print_success("All directories created successfully!")
    else:
        print()
        print_error("Some directories failed to create. Please check permissions.")
        sys.exit(1)
    
    # Generate config file
    generate_config_file(base_dir)
    
    # Print directory structure
    print()
    print_info("Directory Structure:")
    print("====================")
    print(base_dir.name)
    print_directory_tree(base_dir, max_depth=3)
    
    # Print next steps
    print()
    print_info("Next Steps:")
    print("1. Update API keys in config/ENV.json")
    print("2. Review and adjust paths if needed")
    print("3. Install Python dependencies: pip install -r requirements.txt")
    print("4. Start the application: python main.py")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_warning("Setup cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print()
        print_error(f"Unexpected error: {e}")
        sys.exit(1)