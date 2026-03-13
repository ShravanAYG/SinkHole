#!/bin/bash
# Comprehensive test runner for Botwall behavior detection

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}BOTWALL BEHAVIOR TEST RUNNER${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check dependencies
check_deps() {
    echo "Checking dependencies..."
    
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ python3 not found${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ python3${NC}"
    
    if ! command -v ngrok &> /dev/null; then
        echo -e "${YELLOW}⚠ ngrok not found - will install${NC}"
    else
        echo -e "${GREEN}✓ ngrok${NC}"
    fi
    
    echo ""
}

# Create directories
setup_dirs() {
    echo "Setting up directories..."
    mkdir -p /home/bb/sinkhole/logs
    mkdir -p /home/bb/sinkhole/pids
    mkdir -p /home/bb/sinkhole/static
    echo -e "${GREEN}✓ Directories created${NC}"
    echo ""
}

# Start Botwall backend
start_backend() {
    echo "Starting Botwall backend (uvicorn)..."
    
    # Kill existing
    pkill -f "uvicorn botwall.app:app" 2>/dev/null || true
    sleep 1
    
    cd /home/bb/sinkhole
    python3 -m uvicorn botwall.app:app --host 127.0.0.1 --port 4000 --reload > logs/uvicorn.log 2>&1 &
    echo $! > pids/uvicorn.pid
    
    # Wait for startup
    for i in {1..10}; do
        if curl -s http://127.0.0.1:4000/healthz > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Backend started on port 4000${NC}"
            return 0
        fi
        sleep 1
    done
    
    echo -e "${RED}❌ Backend failed to start${NC}"
    cat logs/uvicorn.log
    exit 1
}

# Start ngrok
start_ngrok() {
    echo "Starting ngrok tunnel..."
    
    # Kill existing
    pkill -f "ngrok http" 2>/dev/null || true
    sleep 1
    
    # Check for auth token
    if [ -z "$NGROK_AUTHTOKEN" ]; then
        echo -e "${YELLOW}⚠ NGROK_AUTHTOKEN not set - ngrok may fail${NC}"
        echo "   Set it with: export NGROK_AUTHTOKEN=your_token"
    fi
    
    # Start ngrok
    ngrok http 8000 --log=stdout > logs/ngrok.log 2>&1 &
    echo $! > pids/ngrok.pid
    
    # Wait for tunnel
    sleep 3
    
    # Get public URL
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"[^"]*"' | grep https | head -1 | cut -d'"' -f4)
    
    if [ -n "$NGROK_URL" ]; then
        echo -e "${GREEN}✓ ngrok tunnel active${NC}"
        echo -e "   Public URL: ${YELLOW}$NGROK_URL${NC}"
        echo "$NGROK_URL" > /tmp/ngrok_url.txt
    else
        echo -e "${YELLOW}⚠ ngrok starting... check logs/ngrok.log${NC}"
    fi
}

# Run scraper test
run_scraper_test() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}RUNNING SCRAPER TEST${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    cd /home/bb/sinkhole
    
    # Check if aiohttp is available
    if ! python3 -c "import aiohttp" 2>/dev/null; then
        echo -e "${YELLOW}Installing aiohttp...${NC}"
        pip3 install aiohttp beautifulsoup4 --user 2>/dev/null || pip3 install aiohttp beautifulsoup4 --break-system-packages 2>/dev/null || true
    fi
    
    # Get URL
    if [ -f /tmp/ngrok_url.txt ]; then
        TEST_URL=$(cat /tmp/ngrok_url.txt)
    else
        TEST_URL="http://localhost:8000"
    fi
    
    echo "Testing against: $TEST_URL"
    echo ""
    
    python3 test_scraper.py "$TEST_URL" 2>&1 | tee logs/scraper_test.log
    
    echo ""
    echo -e "${GREEN}Scraper test complete!${NC}"
    echo "   Report: scrape_report.json"
    echo "   Log: logs/scraper_test.log"
}

# Quick curl test
curl_test() {
    echo ""
    echo "Quick endpoint tests..."
    
    BASE="http://localhost:8000"
    
    # Test health
    echo -n "  Health check: "
    curl -s $BASE/health | grep -q "ok" && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"
    
    # Test home
    echo -n "  Home page: "
    curl -s -o /dev/null -w "%{http_code}" $BASE/ | grep -q "200" && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"
    
    # Test check endpoint
    echo -n "  Check endpoint: "
    curl -s -o /dev/null -w "%{http_code}" $BASE/bw/check | grep -q "200" && echo -e "${GREEN}✓${NC}" || echo -e "${RED}✗${NC}"
    
    echo ""
}

# Status check
status() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}SERVICE STATUS${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    
    # Check processes
    for svc in uvicorn ngrok; do
        if [ -f pids/$svc.pid ]; then
            pid=$(cat pids/$svc.pid)
            if kill -0 $pid 2>/dev/null; then
                echo -e "  ${GREEN}✓ $svc${NC} (PID: $pid)"
            else
                echo -e "  ${RED}✗ $svc${NC} (dead)"
            fi
        else
            echo -e "  ${RED}✗ $svc${NC} (not started)"
        fi
    done
    
    echo ""
    
    # URLs
    echo "Local:  http://localhost:8000"
    if [ -f /tmp/ngrok_url.txt ]; then
        echo "Public: $(cat /tmp/ngrok_url.txt)"
    fi
    
    echo ""
    echo "Dashboards:"
    echo "  - Telemetry: http://localhost:8000/dashboard"
    echo "  - Config:    http://localhost:8000/bw/config"
    echo "  - Health:    http://localhost:8000/health"
    
    if [ -f /tmp/ngrok_url.txt ]; then
        echo "  - ngrok:     http://localhost:4040"
    fi
}

# Stop all
stop_all() {
    echo "Stopping services..."
    
    for svc in uvicorn ngrok; do
        if [ -f pids/$svc.pid ]; then
            kill $(cat pids/$svc.pid) 2>/dev/null || true
            rm -f pids/$svc.pid
        fi
    done
    
    pkill -f "uvicorn botwall.app:app" 2>/dev/null || true
    pkill -f "ngrok http" 2>/dev/null || true
    
    echo -e "${GREEN}✓ All services stopped${NC}"
}

# Main
case "${1:-}" in
    start)
        check_deps
        setup_dirs
        start_backend
        start_ngrok
        sleep 2
        curl_test
        status
        ;;
    test)
        run_scraper_test
        ;;
    status)
        status
        ;;
    stop)
        stop_all
        ;;
    restart)
        stop_all
        sleep 2
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|test|status|stop|restart}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all services (backend + ngrok)"
        echo "  test     - Run scraper behavior test"
        echo "  status   - Show service status and URLs"
        echo "  stop     - Stop all services"
        echo "  restart  - Restart all services"
        echo ""
        exit 1
        ;;
esac
