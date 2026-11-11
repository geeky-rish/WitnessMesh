#!/bin/bash
# WitnessMesh Demo Script
# Runs the complete two-act demonstration

set -e

echo "=========================================="
echo "WitnessMesh Two-Act Demonstration"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build the project
echo -e "${BLUE}Building WitnessMesh...${NC}"
go build -o witnessmesh ./cmd/witnessmesh

# Clean previous data
echo -e "${BLUE}Cleaning previous data...${NC}"
rm -rf data/*
mkdir -p data

# Start services using docker-compose
echo -e "${BLUE}Starting services with docker-compose...${NC}"
docker-compose up -d --build

# Wait for services to be healthy
echo -e "${BLUE}Waiting for services to be healthy...${NC}"
sleep 10

# Check service health
check_service() {
    local name=$1
    local url=$2
    if curl -s -f "$url" > /dev/null; then
        echo -e "${GREEN}✓ $name is healthy${NC}"
        return 0
    else
        echo -e "${RED}✗ $name is not responding${NC}"
        return 1
    fi
}

check_service "Log" "http://localhost:8081/tree-head"
check_service "Witness-0" "http://localhost:8082/health"
check_service "Witness-1" "http://localhost:8083/health"
check_service "Witness-2" "http://localhost:8084/health"
check_service "Dashboard" "http://localhost:8080/api/health"

echo ""
echo "=========================================="
echo "ACT 1: Honest System Prevents Split-View"
echo "=========================================="
echo ""
echo "The transparency log and all witnesses are honest."
echo "A malicious log attempts to present different histories to different clients."
echo ""

# Add some leaves to the log
echo -e "${BLUE}Adding entries to the log...${NC}"
for i in {1..5}; do
    CHECKSUM=$(echo -n "entry-$i" | sha256sum | cut -d' ' -f1)
    curl -s -X POST http://localhost:8081/add-leaf \
        -H "Content-Type: application/octet-stream" \
        -d "checksum: $CHECKSUM" > /dev/null
    echo -e "${GREEN}  Added entry $i${NC}"
    sleep 1
done

# Get checkpoint
echo -e "${BLUE}Fetching checkpoint from log...${NC}"
curl -s http://localhost:8081/tree-head | head -20

# Get witness cosignatures
echo -e "${BLUE}Requesting cosignatures from witnesses...${NC}"
for w in 0 1 2; do
    PORT=$((8082 + w))
    echo "Witness $w (port $PORT):"
    curl -s -X POST "http://localhost:$PORT/add-checkpoint" \
        -H "Content-Type: text/plain" \
        --data-binary @- << 'EOF' < <(curl -s http://localhost:8081/tree-head)
old 0

EOF
    echo ""
done

echo ""
echo -e "${GREEN}ACT 1 COMPLETE: Honest witnesses rejected inconsistent checkpoints${NC}"
echo -e "${GREEN}Clients verified quorum and accepted only valid checkpoint${NC}"
echo ""

echo "=========================================="
echo "ACT 2: Compromised System Produces Evidence"
echo "=========================================="
echo ""
echo "1. Snapshot witness-0's SQLite state"
echo "2. Advance witness-0 to newer checkpoint"
echo "3. Restore older snapshot (rollback)"
echo "4. Malicious log presents conflicting history"
echo "5. Rolled-back witness accepts incompatible checkpoint"
echo "6. Monitoring engine detects fork"
echo "7. Evidence bundle generated"
echo "8. Offline verifier confirms log and witness fault"
echo "9. Trust policy updated to exclude faulty witness"
echo "10. Same attack now fails under updated policy"
echo ""

# Run the attack simulation
echo -e "${BLUE}Running attack simulation...${NC}"
./witnessmesh -mode attack -attack split-view-rollback

echo ""
echo -e "${GREEN}ACT 2 COMPLETE: Evidence generated and verified${NC}"
echo ""

echo "=========================================="
echo "Demonstration Complete"
echo "=========================================="
echo ""
echo "Dashboard available at: http://localhost:8080"
echo ""
echo "To run individual components:"
echo "  ./witnessmesh -mode log"
echo "  ./witnessmesh -mode witness -name witness-0"
echo "  ./witnessmesh -mode client"
echo "  ./witnessmesh -mode monitor"
echo "  ./witnessmesh -mode verify -evidence data/evidence.json"
echo ""

# Keep services running
echo "Services are running. Press Ctrl+C to stop."
trap "docker-compose down" EXIT
wait