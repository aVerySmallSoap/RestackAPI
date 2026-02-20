#!/usr/bin/env python3
"""
RestackAPI Master Setup Script
Orchestrates complete setup: directories, Docker images, and configuration.

This is the recommended way to set up RestackAPI from scratch.
"""

import subprocess
import sys
from pathlib import Path


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'


def print_header(message):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{message.center(70)}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 70}{Colors.NC}\n")


def print_info(message):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")


def print_success(message):
    print(f"{Colors.GREEN}[✓]{Colors.NC} {message}")


def print_error(message):
    print(f"{Colors.RED}[✗]{Colors.NC} {message}")


def run_script(script_path: Path, description: str) -> bool:
    """
    Run a setup script
    
    Args:
        script_path: Path to the script
        description: Description of what the script does
        
    Returns:
        True if successful, False otherwise
    """
    print_header(description)
    
    if not script_path.exists():
        print_error(f"Script not found: {script_path}")
        return False
    
    print_info(f"Running: {script_path}")
    print()
    
    try:
        # Determine how to run the script
        if script_path.suffix == '.py':
            result = subprocess.run([sys.executable, str(script_path)], check=False)
        elif script_path.suffix == '.sh':
            result = subprocess.run(['bash', str(script_path)], check=False)
        else:
            print_error(f"Unknown script type: {script_path}")
            return False
        
        if result.returncode == 0:
            print_success(f"Completed: {description}")
            return True
        else:
            print_error(f"Failed: {description}")
            return False
            
    except Exception as e:
        print_error(f"Error running script: {e}")
        return False


def check_prerequisites():
    """Check if basic prerequisites are met"""
    print_header("Checking Prerequisites")
    
    all_good = True
    
    # Check Python version
    if sys.version_info >= (3, 7):
        print_success(f"Python {sys.version_info.major}.{sys.version_info.minor} detected")
    else:
        print_error(f"Python 3.7+ required, found {sys.version_info.major}.{sys.version_info.minor}")
        all_good = False
    
    # Check if Docker is available
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            print_success("Docker detected")
        else:
            print_error("Docker not found")
            all_good = False
    except:
        print_error("Docker not found")
        all_good = False
    
    return all_good


def main():
    """Main orchestration function"""
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔═══════════════════════════════════════════════════════════════════╗")
    print("║                                                                   ║")
    print("║             RestackAPI Complete Setup Wizard                      ║")
    print("║                                                                   ║")
    print("║  This script will set up everything you need to run RestackAPI:   ║")
    print("║    • Directory structure                                          ║")
    print("║    • Docker images                                                ║")
    print("║    • Configuration files                                          ║")
    print("║                                                                   ║")
    print("╚═══════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")
    
    input("Press Enter to continue...")
    
    # Check prerequisites
    if not check_prerequisites():
        print()
        print_error("Prerequisites check failed. Please install missing components.")
        print()
        print("Installation guides:")
        print("  Python: https://www.python.org/downloads/")
        print("  Docker: https://docs.docker.com/get-docker/")
        sys.exit(1)
    
    # Get script directory
    script_dir = Path(__file__).parent
    
    # Setup steps
    steps = [
        {
            'script': script_dir / 'setup_directories.py',
            'description': 'STEP 1: Creating Directory Structure',
            'required': True
        },
        {
            'script': script_dir / 'setup_docker.py',
            'description': 'STEP 2: Setting Up Docker Images',
            'required': False  # Optional if Docker issues
        }
    ]
    
    results = {}
    
    # Run each step
    for step in steps:
        success = run_script(step['script'], step['description'])
        results[step['description']] = success
        
        if not success and step['required']:
            print()
            print_error("A required setup step failed. Cannot continue.")
            sys.exit(1)
        
        if not success and not step['required']:
            print()
            user_input = input("This step failed. Continue anyway? [y/N]: ").strip().lower()
            if user_input not in ['y', 'yes']:
                print_error("Setup cancelled by user.")
                sys.exit(1)
    
    # Final summary
    print_header("Setup Complete!")
    
    print("Summary:")
    for description, success in results.items():
        icon = "✓" if success else "✗"
        color = Colors.GREEN if success else Colors.RED
        print(f"  {color}{icon}{Colors.NC} {description.split(':')[1].strip()}")
    
    print()
    print_info("Next Steps:")
    print("  1. Update API keys in config/ENV.json:")
    print(f"     {Colors.YELLOW}nano config/ENV.json{Colors.NC} (or your preferred editor)")
    print()
    print("  2. Install Python dependencies:")
    print(f"     {Colors.YELLOW}pip install -r requirements.txt{Colors.NC}")
    print()
    print("  3. Start the application:")
    print(f"     {Colors.YELLOW}python main.py{Colors.NC}")
    print()
    
    print_success("You're all set!")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_error("Setup cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print()
        print_error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)