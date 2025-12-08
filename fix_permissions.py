#!/usr/bin/env python3
"""
Fix permissions for Restack API directories.
This script attempts to fix permission issues caused by Docker containers.

Usage:
    python fix_permissions.py              # Try without sudo first
    sudo python fix_permissions.py         # If the above fails
"""

import os
import subprocess
import sys
from pathlib import Path


def run_command(cmd, ignore_errors=True):
    """Run a shell command."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0 and not ignore_errors:
            print(f"Warning: {cmd} failed: {result.stderr}")
        return result.returncode == 0
    except Exception as e:
        if not ignore_errors:
            print(f"Error running {cmd}: {e}")
        return False


def main():
    # Get script directory
    script_dir = Path(__file__).parent.absolute()
    os.chdir(script_dir)

    print("🔧 Fixing permissions for Restack API directories...")
    print(f"📁 Working directory: {script_dir}")
    print()

    # Directories to fix
    directories = [
        "temp/whatweb",
        "temp/zap",
        "temp/search_vulns",
        "reports/wapiti",
        "reports/full_scan",
        "reports/exports",
        "logs",
    ]

    # Create directories
    print("📂 Creating directories...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory}")

    print()

    # Check if we're root or have sudo
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

    if is_root:
        print("🔐 Running with elevated privileges")

        # Get the actual user (if run with sudo)
        actual_user = os.environ.get("SUDO_USER", os.environ.get("USER", "root"))

        print(f"👤 Setting owner to: {actual_user}")
        print()

        # Change ownership
        for directory in ["temp", "reports", "logs"]:
            if Path(directory).exists():
                success = run_command(
                    f"chown -R {actual_user}:{actual_user} {directory}"
                )
                if success:
                    print(f"  ✓ Changed ownership of {directory}/")
    else:
        print("⚠️  Not running as root - will attempt chmod only")
        print("   If this fails, try: sudo python fix_permissions.py")
        print()

    # Set permissions
    print("🔓 Setting permissions...")
    for directory in ["temp", "reports", "logs"]:
        if Path(directory).exists():
            success = run_command(f"chmod -R 755 {directory}")
            if success:
                print(f"  ✓ Set permissions on {directory}/")

            # Make files readable/writable
            run_command(f"find {directory} -type f -exec chmod 666 {{}} \\;")

    print()
    print("✅ Permission fix completed!")
    print()

    # Show current state
    print("📊 Current directory permissions:")
    for directory in ["temp", "reports", "logs"]:
        if Path(directory).exists():
            run_command(f"ls -la {directory}")

    print()
    print("💡 Tips to avoid permission issues:")
    print()
    print("1. Add your user to the docker group:")
    print("   sudo usermod -aG docker $USER")
    print("   newgrp docker")
    print("   # Then log out and back in")
    print()
    print("2. Or run this script after Docker operations:")
    print("   python fix_permissions.py")
    print()
    print("3. The application now tries to auto-fix permissions,")
    print("   but manual fixing may still be needed occasionally.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        sys.exit(1)
