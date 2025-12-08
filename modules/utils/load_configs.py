import json
import os

# Get the project root directory (two levels up from this file)
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.normpath(os.path.join(script_dir, "..", ".."))

config_dir = os.path.join(project_root, "config")
templates_dir = os.path.join(project_root, "templates")


def resolve_paths(config_dict, base_dir):
    """
    Recursively resolve relative paths in configuration to absolute paths.

    Args:
        config_dict: Dictionary containing configuration
        base_dir: Base directory to resolve relative paths against

    Returns:
        Modified dictionary with absolute paths
    """
    for key, value in config_dict.items():
        if isinstance(value, dict):
            # Recursively process nested dictionaries
            resolve_paths(value, base_dir)
        elif isinstance(value, str) and value:
            # If it's a non-empty string, check if it looks like a path
            # (contains path separators or common path patterns)
            if (
                os.sep in value
                or "/" in value
                or value.endswith((".json", ".xml", ".txt"))
            ):
                # Convert to absolute path if it's relative
                if not os.path.isabs(value):
                    config_dict[key] = os.path.abspath(os.path.join(base_dir, value))

    return config_dict


try:
    # Load the configuration files
    with open(os.path.join(config_dir, "ENV.json"), "r") as f:
        DEV_ENV = json.load(f)

    # Resolve all relative paths to absolute paths based on project root
    DEV_ENV = resolve_paths(DEV_ENV, project_root)

    with open(os.path.join(templates_dir, "wapiti_config.json"), "r") as f:
        DEV_WAPITI_CONFIG = json.load(f)

    with open(os.path.join(templates_dir, "zap_template.json"), "r") as f:
        DEV_ZAP_TEMPLATE = json.load(f)

except FileNotFoundError as e:
    print("Error: A required configuration file was not found.")
    print(f"Missing file: {e}")
    print(f"Project root: {project_root}")
    print(f"Config directory: {config_dir}")
    print(f"Templates directory: {templates_dir}")
    DEV_ENV, DEV_WAPITI_CONFIG, DEV_ZAP_TEMPLATE = (
        None,
        None,
        None,
    )
    exit()
