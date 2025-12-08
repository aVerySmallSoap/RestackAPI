"""
Cross-platform subprocess utilities for Restack API.
Handles OS-specific subprocess creation flags.
"""

import os
import subprocess
from typing import Any, Dict, List


def get_subprocess_kwargs(detached: bool = True) -> Dict[str, Any]:
    """
    Get platform-specific subprocess.Popen kwargs.

    Args:
        detached: Whether to create a detached process (Windows only)

    Returns:
        Dictionary of kwargs for subprocess.Popen
    """
    kwargs = {}

    if os.name == "nt":  # Windows
        if detached:
            # DETACHED_PROCESS = 0x00000008
            # CREATE_NO_WINDOW = 0x08000000
            kwargs["creationflags"] = (
                subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
            )
    else:  # Unix/Linux/macOS
        if detached:
            # On Unix, we can use start_new_session to detach
            kwargs["start_new_session"] = True

    return kwargs


def run_detached_process(command: List[str], **additional_kwargs) -> subprocess.Popen:
    """
    Run a command in a detached process (cross-platform).

    Args:
        command: Command and arguments as a list
        **additional_kwargs: Additional kwargs to pass to Popen

    Returns:
        subprocess.Popen instance
    """
    popen_kwargs = get_subprocess_kwargs(detached=True)
    popen_kwargs.update(additional_kwargs)

    return subprocess.Popen(command, **popen_kwargs)


def run_command_sync(
    command: List[str], detached: bool = False, **additional_kwargs
) -> subprocess.Popen:
    """
    Run a command synchronously and wait for completion.

    Args:
        command: Command and arguments as a list
        detached: Whether to run detached from parent process
        **additional_kwargs: Additional kwargs to pass to Popen

    Returns:
        subprocess.Popen instance (after wait() completes)
    """
    popen_kwargs = get_subprocess_kwargs(detached=detached)
    popen_kwargs.update(additional_kwargs)

    process = subprocess.Popen(command, **popen_kwargs)
    process.wait()

    return process
