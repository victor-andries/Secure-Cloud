#!/usr/bin/env bash
# Start the full dev environment with hot reload
# Usage: bash start-dev.sh

set -e

# Detect python command
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
  echo "Error: python3 or python not found. Install Python 3.10+ first."
  exit 1
fi
echo "Using Python: $PYTHON"

echo "Starting infrastructure (MinIO + Redis)..."
docker-compose -f docker-compose.dev.yml up -d

echo "Waiting for MinIO and Redis..."
sleep 3

export FLASK_DEBUG=1

echo "Setting up Python virtual environment..."
cd backend
if [ ! -d "venv" ]; then
  $PYTHON -m venv venv
  echo "Virtual environment created."
fi

# Activate venv
source venv/bin/activate || source venv/Scripts/activate

echo "Installing backend dependencies..."
pip install -r requirements.txt -q
echo "Backend dependencies ready."

PYTHON=$(command -v python)

$PYTHON storage_service.py &
STORAGE_PID=$!

$PYTHON blockchain_service.py &
BLOCKCHAIN_PID=$!

$PYTHON ai_detection_service.py &
AI_PID=$!

$PYTHON main.py &
GATEWAY_PID=$!

cd ..

echo "Starting frontend..."
cd frontend
npm install -q
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "All services running:"
echo "  Frontend:   http://localhost:3000"
echo "  Gateway:    http://localhost:5000"
echo "  Storage:    http://localhost:5001"
echo "  Blockchain: http://localhost:5002"
echo "  AI:         http://localhost:5003"
echo "  MinIO UI:   http://localhost:9001"
echo ""
echo "Press Ctrl+C to stop all services"

# Stop all on Ctrl+C
trap "kill $STORAGE_PID $BLOCKCHAIN_PID $AI_PID $GATEWAY_PID $FRONTEND_PID 2>/dev/null; docker-compose -f docker-compose.dev.yml down" EXIT

wait
