#!/usr/bin/env python3
"""
RestackAPI Docker Setup Script
Automates Docker image pulling and building for the security scanning application.

Required Docker images:
- zaproxy/zap-stable (OWASP ZAP)
- iamyourdev/whatweb (WhatWeb fingerprinting)
- search_vulns (custom build from tools/search_vulns/)
- projectdiscovery/subfinder (subdomain discovery)
- projectdiscovery/nuclei (vulnerability scanner)
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'
    
    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = cls.CYAN = cls.NC = ''


if sys.platform == 'win32' and not os.environ.get('ANSICON'):
    Colors.disable()


def print_info(message):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")


def print_success(message):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {message}")


def print_warning(message):
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")


def print_error(message):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")


def print_step(message):
    print(f"{Colors.CYAN}[STEP]{Colors.NC} {message}")


def check_docker_installed() -> bool:
    """
    Check if Docker is installed and running
    
    Returns:
        True if Docker is available, False otherwise
    """
    try:
        result = subprocess.run(
            ['docker', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print_success(f"Docker found: {result.stdout.strip()}")
            return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_docker_running() -> bool:
    """
    Check if Docker daemon is running
    
    Returns:
        True if Docker daemon is running, False otherwise
    """
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def pull_docker_image(image_name: str, tag: str = 'latest') -> bool:
    """
    Pull a Docker image from registry
    
    Args:
        image_name: Name of the Docker image
        tag: Image tag (default: latest)
        
    Returns:
        True if successful, False otherwise
    """
    full_image = f"{image_name}:{tag}" if tag != 'latest' else image_name
    print_step(f"Pulling {full_image}...")
    
    try:
        process = subprocess.Popen(
            ['docker', 'pull', full_image],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Show progress
        for line in process.stdout:
            print(f"  {line.strip()}")
        
        process.wait()
        
        if process.returncode == 0:
            print_success(f"Successfully pulled {full_image}")
            return True
        else:
            print_error(f"Failed to pull {full_image}")
            return False
            
    except Exception as e:
        print_error(f"Error pulling {full_image}: {e}")
        return False


def build_docker_image(dockerfile_path: Path, image_name: str, context_path: Path = None) -> bool:
    """
    Build a Docker image from Dockerfile
    
    Args:
        dockerfile_path: Path to Dockerfile
        image_name: Name to tag the built image
        context_path: Build context directory (defaults to Dockerfile directory)
        
    Returns:
        True if successful, False otherwise
    """
    if not dockerfile_path.exists():
        print_error(f"Dockerfile not found: {dockerfile_path}")
        return False
    
    if context_path is None:
        context_path = dockerfile_path.parent
    
    print_step(f"Building {image_name} from {dockerfile_path}...")
    
    try:
        process = subprocess.Popen(
            ['docker', 'build', '-t', image_name, '-f', str(dockerfile_path), str(context_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Show progress
        for line in process.stdout:
            print(f"  {line.strip()}")
        
        process.wait()
        
        if process.returncode == 0:
            print_success(f"Successfully built {image_name}")
            return True
        else:
            print_error(f"Failed to build {image_name}")
            return False
            
    except Exception as e:
        print_error(f"Error building {image_name}: {e}")
        return False


def check_image_exists(image_name: str) -> bool:
    """
    Check if a Docker image exists locally
    
    Args:
        image_name: Name of the Docker image
        
    Returns:
        True if image exists, False otherwise
    """
    try:
        result = subprocess.run(
            ['docker', 'images', '-q', image_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return bool(result.stdout.strip())
    except:
        return False


def list_docker_images() -> List[str]:
    """
    List all Docker images
    
    Returns:
        List of image names
    """
    try:
        result = subprocess.run(
            ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')
        return []
    except:
        return []


def setup_custom_images(tools_dir: Path, force_rebuild: bool = False) -> Dict[str, bool]:
    """
    Build custom Docker images from tools directory
    
    Args:
        tools_dir: Path to tools directory containing Dockerfiles
        force_rebuild: Force rebuild even if image exists
        
    Returns:
        Dictionary of image names and build success status
    """
    results = {}
    
    # The actual Dockerfile location for search_vulns
    searchvulns_dockerfile = tools_dir / 'searchvulns.dockerfile'
    
    if not tools_dir.exists():
        print_warning(f"Tools directory not found: {tools_dir}")
        return results
    
    # Build search_vulns from tools/searchvulns.dockerfile
    if searchvulns_dockerfile.exists():
        image_name = 'search_vulns'
        
        # Check if image already exists
        if check_image_exists(image_name) and not force_rebuild:
            print_info(f"Image {image_name} already exists, skipping build")
            print_info(f"Use --force-rebuild to rebuild existing images")
            results[image_name] = True
        else:
            # Build with tools directory as context
            print_info(f"Building from: {searchvulns_dockerfile}")
            results[image_name] = build_docker_image(
                searchvulns_dockerfile, 
                image_name, 
                context_path=tools_dir
            )
    else:
        print_warning(f"Dockerfile not found: {searchvulns_dockerfile}")
        print_info("Expected location: tools/searchvulns.dockerfile")
        print_info("Clone from: https://github.com/ra1nb0rn/search_vulns")
        results['search_vulns'] = False
    
    return results


def main():
    """Main setup function"""
    print()
    print("=" * 60)
    print("RestackAPI Docker Setup")
    print("=" * 60)
    print()
    
    # Parse arguments
    force_rebuild = '--force-rebuild' in sys.argv or '-f' in sys.argv
    skip_pull = '--skip-pull' in sys.argv
    
    # Check Docker installation
    print_step("Checking Docker installation...")
    if not check_docker_installed():
        print_error("Docker is not installed!")
        print()
        print("Please install Docker:")
        print("  Linux:   https://docs.docker.com/engine/install/")
        print("  macOS:   https://docs.docker.com/desktop/install/mac-install/")
        print("  Windows: https://docs.docker.com/desktop/install/windows-install/")
        sys.exit(1)
    
    print()
    print_step("Checking Docker daemon...")
    if not check_docker_running():
        print_error("Docker daemon is not running!")
        print("Please start Docker and try again.")
        sys.exit(1)
    
    print_success("Docker daemon is running")
    print()
    
    # Define images to pull
    public_images = [
        ('zaproxy/zap-stable', 'OWASP ZAP - Web Application Security Scanner'),
        ('iamyourdev/whatweb', 'WhatWeb - Web Technology Fingerprinting'),
        ('projectdiscovery/subfinder', 'Subfinder - Subdomain Discovery Tool'),
        ('projectdiscovery/nuclei', 'Nuclei - Vulnerability Scanner'),
    ]
    
    pull_results = {}
    
    if not skip_pull:
        print("=" * 60)
        print("PULLING PUBLIC DOCKER IMAGES")
        print("=" * 60)
        print()
        
        for image_name, description in public_images:
            print(f"{description}")
            
            # Check if already exists
            if check_image_exists(image_name):
                print_info(f"Image {image_name} already exists locally")
                user_input = input(f"  Re-pull to update? [y/N]: ").strip().lower()
                if user_input not in ['y', 'yes']:
                    print_info(f"Skipping {image_name}")
                    pull_results[image_name] = True
                    print()
                    continue
            
            pull_results[image_name] = pull_docker_image(image_name)
            print()
            time.sleep(1)  # Brief pause between pulls
    else:
        print_warning("Skipping public image pulls (--skip-pull flag)")
        print()
    
    # Build custom images
    print("=" * 60)
    print("BUILDING CUSTOM DOCKER IMAGES")
    print("=" * 60)
    print()
    
    tools_dir = Path('tools')
    if not tools_dir.exists():
        print_warning(f"Tools directory not found: {tools_dir}")
        print_info("Looking for tools directory in common locations...")
        
        # Try alternate locations
        possible_paths = [
            Path.cwd() / 'tools',
            Path.cwd().parent / 'tools',
            Path(__file__).parent / 'tools',
        ]
        
        for path in possible_paths:
            if path.exists():
                tools_dir = path
                print_success(f"Found tools directory: {tools_dir}")
                break
        else:
            print_warning("No tools directory found, skipping custom builds")
            tools_dir = None
    
    build_results = {}
    if tools_dir:
        build_results = setup_custom_images(tools_dir, force_rebuild)
        print()
    
    # Summary
    print("=" * 60)
    print("SETUP SUMMARY")
    print("=" * 60)
    print()
    
    total_success = 0
    total_failed = 0
    
    if not skip_pull:
        print("Public Images:")
        for image_name, description in public_images:
            status = pull_results.get(image_name, False)
            icon = "✓" if status else "✗"
            color = Colors.GREEN if status else Colors.RED
            print(f"  {color}{icon}{Colors.NC} {image_name}")
            if status:
                total_success += 1
            else:
                total_failed += 1
        print()
    
    if build_results:
        print("Custom Images:")
        for image_name, status in build_results.items():
            icon = "✓" if status else "✗"
            color = Colors.GREEN if status else Colors.RED
            print(f"  {color}{icon}{Colors.NC} {image_name}")
            if status:
                total_success += 1
            else:
                total_failed += 1
        print()
    
    # Show available images
    print("Available Docker Images:")
    images = list_docker_images()
    relevant_images = [img for img in images if any(
        name in img.lower() for name in ['zap', 'whatweb', 'subfinder', 'nuclei', 'search_vulns']
    )]
    for img in relevant_images[:10]:  # Limit to 10
        print(f"  • {img}")
    print()
    
    # Final status
    if total_failed == 0:
        print_success(f"All {total_success} images ready!")
        print()
        print_info("Next steps:")
        print("  1. Run: python setup_directories.py")
        print("  2. Update config/ENV.json with API keys")
        print("  3. Start application: python main.py")
    else:
        print_warning(f"{total_success} succeeded, {total_failed} failed")
        print()
        print_info("You can retry failed images by running this script again")
        print_info("Use --force-rebuild to rebuild existing images")
    
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
        import traceback
        traceback.print_exc()
        sys.exit(1)