@echo off
REM Censys AI Agent Startup Script for Windows

echo 🎯 Starting Censys AI Agent...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed.
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js is required but not installed.
    pause
    exit /b 1
)

echo 🚀 Starting backend server...
cd backend

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo 📥 Installing backend dependencies...
pip install -r requirements.txt

REM Start backend server
echo 🔧 Starting FastAPI server on http://localhost:8000
start "Backend Server" cmd /k "python run.py"

cd ..

echo 🎨 Starting frontend server...
cd frontend

REM Install dependencies
echo 📥 Installing frontend dependencies...
npm install

REM Start frontend server
echo 🎨 Starting React development server on http://localhost:3000
start "Frontend Server" cmd /k "npm start"

cd ..

echo.
echo ✅ Censys AI Agent is starting!
echo 🌐 Frontend: http://localhost:3000
echo 🔧 Backend API: http://localhost:8000
echo 📚 API Documentation: http://localhost:8000/docs
echo.
echo Press any key to exit...
pause >nul
