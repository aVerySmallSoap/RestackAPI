"""
Cross-platform path utilities for handling file paths across Windows and Unix systems.
"""
import os
import platform
from pathlib import Path


def get_temp_base_dir():
    """Get the appropriate temp directory for the current OS."""
    if platform.system() == "Windows":
        return os.path.join(os.environ.get("USERPROFILE", "C:\\"), "AppData", "Local", "Temp", "RestackAPI")
    else:
        # Unix systems - use /tmp or user's home
        return os.path.join(os.environ.get("HOME", "/tmp"), ".RestackAPI")


def ensure_dir_exists(path):
    """Create directory if it doesn't exist."""
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def get_report_path(*parts):
    """Build a cross-platform path using os.path.join."""
    return os.path.join(*parts)


def normalize_path(path_str):
    """
    Convert Windows-style paths to OS-appropriate paths.
    Replaces %USERPROFILE% and backslashes.
    """
    if not path_str:
        return path_str
    
    # Replace Windows environment variables
    if "%USERPROFILE%" in path_str:
        if platform.system() == "Windows":
            path_str = path_str.replace("%USERPROFILE%", os.environ.get("USERPROFILE", "C:\\"))
        else:
            # Convert to Unix home directory
            path_str = path_str.replace("%USERPROFILE%\\AppData\\Local\\Temp", 
                                       os.environ.get("HOME", "/tmp"))
    
    # Convert backslashes to forward slashes, then use os.path for normalization
    path_str = path_str.replace("\\", "/")
    
    # Use pathlib for final normalization
    return str(Path(path_str))
