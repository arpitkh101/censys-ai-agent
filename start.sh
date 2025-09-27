#!/bin/bash

# Censys AI Agent Startup Script
echo "🎯 Starting Censys AI Agent..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi

# Function to start backend
start_backend() {
    echo "🚀 Starting backend server..."
    cd backend
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo "📦 Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    echo "📥 Installing backend dependencies..."
    pip install -r requirements.txt
    
    # Start backend server
    echo "🔧 Starting FastAPI server on http://localhost:8000"
    python run.py &
    BACKEND_PID=$!
    
    cd ..
}

# Function to start frontend
start_frontend() {
    echo "🎨 Starting frontend server..."
    cd frontend
    
    # Install dependencies
    echo "📥 Installing frontend dependencies..."
    npm install
    
    # Start frontend server
    echo "🎨 Starting React development server on http://localhost:3000"
    npm start &
    FRONTEND_PID=$!
    
    cd ..
}

# Function to cleanup on exit
cleanup() {
    echo "🛑 Shutting down servers..."
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start both servers
start_backend
sleep 3  # Give backend time to start
start_frontend

echo ""
echo "✅ Censys AI Agent is running!"
echo "🌐 Frontend: http://localhost:3000"
echo "🔧 Backend API: http://localhost:8000"
echo "📚 API Documentation: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all servers"

# Wait for user to stop
wait
