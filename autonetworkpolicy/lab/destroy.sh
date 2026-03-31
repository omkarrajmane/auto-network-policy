#!/bin/bash
# Destroy script for AutoNetworkPolicy Containerlab
# Usage: ./destroy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="autonp-lab"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== AutoNetworkPolicy Lab Cleanup ==="
echo ""

# Check if Containerlab is installed
if ! command -v clab &> /dev/null; then
    echo -e "${RED}Error: Containerlab (clab) is not installed${NC}"
    exit 1
fi

cd "$SCRIPT_DIR"

# Check if topology is deployed
if clab inspect --topo lab.clab.yml &> /dev/null; then
    echo -e "${YELLOW}Destroying Containerlab topology...${NC}"
    clab destroy --topo lab.clab.yml --cleanup
    echo -e "${GREEN}✓ Topology destroyed${NC}"
else
    echo -e "${YELLOW}No active topology found${NC}"
fi

# Clean up any remaining containers with our project name prefix
echo ""
echo -e "${YELLOW}Cleaning up remaining containers...${NC}"
REMAINING=$(docker ps -a --format '{{.Names}}' | grep "^${PROJECT_NAME}-" || true)

if [ -n "$REMAINING" ]; then
    echo "Removing containers:"
    echo "$REMAINING"
    docker ps -a --format '{{.Names}}' | grep "^${PROJECT_NAME}-" | xargs -r docker rm -f
    echo -e "${GREEN}✓ Remaining containers removed${NC}"
else
    echo -e "${GREEN}✓ No remaining containers${NC}"
fi

# Clean up any leftover networks
echo ""
echo -e "${YELLOW}Cleaning up networks...${NC}"
NETWORKS=$(docker network ls --format '{{.Name}}' | grep "${PROJECT_NAME}" || true)

if [ -n "$NETWORKS" ]; then
    echo "$NETWORKS" | while read -r network; do
        docker network rm "$network" 2>/dev/null || true
    done
    echo -e "${GREEN}✓ Networks cleaned up${NC}"
else
    echo -e "${GREEN}✓ No leftover networks${NC}"
fi

echo ""
echo -e "${GREEN}=== Cleanup complete ===${NC}"
