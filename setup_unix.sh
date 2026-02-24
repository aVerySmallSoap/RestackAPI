#!/bin/bash

# RestackAPI Unix Setup Script
# This script creates the necessary directory structure for RestackAPI on Unix systems

set -e # Exit on error

echo "=========================================="
echo "RestackAPI Unix Environment Setup"
echo "=========================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BASE_DIR="$HOME/.RestackAPI"

echo "Creating directory structure in: $BASE_DIR"
echo ""

# Create base directory
mkdir -p "$BASE_DIR"

# Create template directories
echo -e "${YELLOW}Creating template directories...${NC}"
mkdir -p "$BASE_DIR/templates"

# Create report directories
echo -e "${YELLOW}Creating report directories...${NC}"
mkdir -p "$BASE_DIR/reports/wapiti"
mkdir -p "$BASE_DIR/reports/full_scan"
mkdir -p "$BASE_DIR/reports/quick_scan"

# Create temp directories
echo -e "${YELLOW}Creating temp directories...${NC}"
mkdir -p "$BASE_DIR/temp/whatweb"
mkdir -p "$BASE_DIR/temp/zap"
mkdir -p "$BASE_DIR/temp/search_vulns"

# Create discovery directories
echo -e "${YELLOW}Creating discovery directories...${NC}"
mkdir -p "$BASE_DIR/tmp/discovery/subfinder"

# Create vulnerability scanner directories
echo -e "${YELLOW}Creating vulnerability directories...${NC}"
mkdir -p "$BASE_DIR/tmp/vulnerabilities/nuclei"

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chmod -R 755 "$BASE_DIR"

echo ""
echo -e "${GREEN}✓ Directory structure created successfully!${NC}"
echo ""

# Create template files if they don't exist
echo -e "${YELLOW}Creating default template files...${NC}"

# Wapiti config template
WAPITI_TEMPLATE="$BASE_DIR/templates/wapiti_config.json"
if [ ! -f "$WAPITI_TEMPLATE" ]; then
    cat >"$WAPITI_TEMPLATE" <<'EOF'
{
  "url": "",
  "modules": ["all"],
  "path": "",
  "scan_type": "normal",
  "scan_time": "180",
  "concurrent_tasks": "2",
  "is_overridden": false,
  "custom_args": []
}
EOF
    echo -e "${GREEN}✓ Created: $WAPITI_TEMPLATE${NC}"
fi

# Active scan template
ACTIVE_SCAN_TEMPLATE="$BASE_DIR/templates/active_scan.json"
if [ ! -f "$ACTIVE_SCAN_TEMPLATE" ]; then
    cat >"$ACTIVE_SCAN_TEMPLATE" <<'EOF'
{
  "scan_type": "active",
  "config": {}
}
EOF
    echo -e "${GREEN}✓ Created: $ACTIVE_SCAN_TEMPLATE${NC}"
fi

echo ""
echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo "==========================================${NC}"
echo ""
echo "Directory structure:"
echo "  $BASE_DIR/"
echo "  ├── templates/"
echo "  ├── reports/"
echo "  │   ├── wapiti/"
echo "  │   ├── full_scan/"
echo "  │   └── quick_scan/"
echo "  ├── temp/"
echo "  │   ├── whatweb/"
echo "  │   ├── zap/"
echo "  │   └── search_vulns/"
echo "  └── tmp/"
echo "      ├── discovery/subfinder/"
echo "      └── vulnerabilities/nuclei/"
echo ""
echo "Next steps:"
echo "  1. Copy config/sample_env.json to config/ENV.json"
echo "  2. Configure API keys and database connections in ENV.json"
echo "  3. Run modules/db/database.py to migrate database"
echo ""
