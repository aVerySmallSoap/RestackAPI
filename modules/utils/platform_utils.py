import platform
import os

def is_windows():
    return platform.system() == "Windows"

def is_linux():
    return platform.system() == "Linux"

def is_macos():
    return platform.system() == "Darwin"

def get_os_name():
    return platform.system()

def get_subprocess_flags():
    """Get appropriate subprocess creation flags for the OS."""
    if is_windows():
        import subprocess
        return subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
    return 0