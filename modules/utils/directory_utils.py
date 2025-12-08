"""
Cross-platform directory and file permission utilities for Restack API.
"""

import os
import stat
from pathlib import Path

from loguru import logger


def ensure_directory_exists(directory_path: str, mode: int = 0o777) -> bool:
    """
    Ensure a directory exists with proper permissions.

    Args:
        directory_path: Path to the directory
        mode: Permission mode (default: 0o777 for read/write/execute for all)

    Returns:
        True if directory exists or was created successfully
    """
    try:
        path = Path(directory_path)

        if not path.exists():
            # Create directory with parents and proper permissions
            path.mkdir(parents=True, exist_ok=True, mode=mode)
            logger.info(f"Created directory: {directory_path}")

        # Ensure directory has proper permissions (especially important after Docker operations)
        try:
            os.chmod(directory_path, mode)
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not set permissions on {directory_path}: {e}")

        return True

    except Exception as e:
        logger.error(f"Failed to ensure directory exists: {directory_path} - {e}")
        return False


def ensure_file_readable(file_path: str, mode: int = 0o666) -> bool:
    """
    Ensure a file is readable with proper permissions.

    Args:
        file_path: Path to the file
        mode: Permission mode (default: 0o666 for read/write for all)

    Returns:
        True if file is readable
    """
    try:
        path = Path(file_path)

        if not path.exists():
            logger.warning(f"File does not exist: {file_path}")
            return False

        # Try to set proper permissions
        try:
            os.chmod(file_path, mode)
        except (OSError, PermissionError) as e:
            logger.warning(f"Could not set permissions on {file_path}: {e}")

        # Test if file is readable
        if os.access(file_path, os.R_OK):
            return True
        else:
            logger.error(f"File exists but is not readable: {file_path}")
            return False

    except Exception as e:
        logger.error(f"Failed to check file readability: {file_path} - {e}")
        return False


def fix_directory_permissions_recursive(
    directory_path: str, dir_mode: int = 0o777, file_mode: int = 0o666
):
    """
    Recursively fix permissions for a directory and all its contents.
    Useful after Docker containers create files as root.

    Args:
        directory_path: Root directory path
        dir_mode: Permission mode for directories
        file_mode: Permission mode for files
    """
    try:
        path = Path(directory_path)

        if not path.exists():
            logger.warning(f"Directory does not exist: {directory_path}")
            return

        # Fix directory permission
        try:
            os.chmod(directory_path, dir_mode)
        except (OSError, PermissionError) as e:
            logger.warning(
                f"Could not set directory permissions on {directory_path}: {e}"
            )

        # Recursively fix permissions for all contents
        for item in path.rglob("*"):
            try:
                if item.is_dir():
                    os.chmod(item, dir_mode)
                else:
                    os.chmod(item, file_mode)
            except (OSError, PermissionError) as e:
                logger.warning(f"Could not set permissions on {item}: {e}")

        logger.info(f"Fixed permissions recursively for: {directory_path}")

    except Exception as e:
        logger.error(f"Failed to fix permissions recursively: {directory_path} - {e}")


def get_file_permissions(file_path: str) -> str:
    """
    Get human-readable file permissions.

    Args:
        file_path: Path to the file

    Returns:
        String representation of permissions (e.g., "rw-r--r--")
    """
    try:
        st = os.stat(file_path)
        mode = st.st_mode

        perms = stat.filemode(mode)
        owner_uid = st.st_uid

        return f"{perms} (owner: {owner_uid})"

    except Exception as e:
        return f"Error: {e}"
