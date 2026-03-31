#!/bin/bash
# Deploy script for AutoNetworkPolicy Containerlab
# Usage: ./deploy.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="autonp-lab"
IMAGE_NAME="autonp-node:latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== AutoNetworkPolicy Lab Deployment ==="
echo ""

# Check if Containerlab is installed
if ! command -v clab &> /dev/null; then
    echo -e "${RED}Error: Containerlab (clab) is not installed${NC}"
    echo "Please install Containerlab first:"
    echo "  curl -sL https://get.containerlab.dev | sudo bash"
    exit 1
fi

echo -e "${GREEN}✓ Containerlab found${NC}"

# Check if Docker is installed and running
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is running${NC}"

# Build Docker image if it doesn't exist or if Dockerfile is newer
if ! docker image inspect "$IMAGE_NAME" &> /dev/null; then
    echo -e "${YELLOW}Building Docker image: $IMAGE_NAME${NC}"
    cd "$SCRIPT_DIR"
    docker build -t "$IMAGE_NAME" .
    echo -e "${GREEN}✓ Docker image built successfully${NC}"
else
    echo -e "${GREEN}✓ Docker image exists: $IMAGE_NAME${NC}"
fi

# Deploy the topology
echo ""
echo -e "${YELLOW}Deploying Containerlab topology...${NC}"
cd "$SCRIPT_DIR"
clab deploy --topo lab.clab.yml

# Verify all nodes are running
echo ""
echo -e "${YELLOW}Verifying node status...${NC}"
sleep 2

NODES=("fw" "client" "server" "attacker")
ALL_RUNNING=true

for node in "${NODES[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "${PROJECT_NAME}-${node}"; then
        echo -e "${GREEN}✓ Node '$node' is running${NC}"
    else
        echo -e "${RED}✗ Node '$node' is NOT running${NC}"
        ALL_RUNNING=false
    fi
done

echo ""
if [ "$ALL_RUNNING" = true ]; then
    echo -e "${GREEN}=== Deployment successful! ===${NC}"
    echo ""
    echo "Lab topology:"
    echo "  fw       - Firewall (nftables)"
    echo "  client   - Traffic generator (iperf3 client, hping3)"
    echo "  server   - Traffic receiver (iperf3 server)"
    echo "  attacker - Adversarial testing node"
    echo ""
    echo "Useful commands:"
    echo "  clab inspect --topo lab.clab.yml     - View topology"
    echo "  clab exec --topo lab.clab.yml --label clab-node-kind=linux --cmd 'ip addr'"
    echo "  docker exec -it ${PROJECT_NAME}-fw sh     - Access firewall"
    echo "  ./destroy.sh                          - Destroy lab"
else
    echo -e "${RED}=== Deployment incomplete - some nodes failed ===${NC}"
    exit 1
fi
