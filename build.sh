#!/bin/bash

# CTI Platform Build Script
# This script builds the complete CTI Platform as a single binary

set -e

echo "🚀 Building CTI Platform..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "build.sh" ]; then
    print_error "Please run this script from the CTI Platform root directory"
    exit 1
fi

# Step 1: Build Frontend
print_status "Step 1: Building React frontend..."
cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    print_status "Installing frontend dependencies..."
    npm install
fi

# Build the frontend
print_status "Building frontend for production..."
npm run build

if [ $? -eq 0 ]; then
    print_success "Frontend build completed successfully"
else
    print_error "Frontend build failed"
    exit 1
fi

cd ..

# Step 2: Copy frontend assets to backend
print_status "Step 2: Copying frontend assets to backend..."
mkdir -p backend/web/static
cp -r frontend/dist/* backend/web/static/

if [ $? -eq 0 ]; then
    print_success "Frontend assets copied to backend"
else
    print_error "Failed to copy frontend assets"
    exit 1
fi

# Step 3: Build Backend
print_status "Step 3: Building Go backend with embedded frontend..."
cd backend

# Build the binary
BINARY_NAME="cti-platform"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    BINARY_NAME="cti-platform.exe"
fi

print_status "Building binary: $BINARY_NAME"
go build -o "$BINARY_NAME" ./cmd/server

if [ $? -eq 0 ]; then
    print_success "Backend build completed successfully"
    print_success "Binary created: backend/$BINARY_NAME"
else
    print_error "Backend build failed"
    exit 1
fi

cd ..

# Step 4: Final success message
print_success "🎉 CTI Platform build completed successfully!"
echo ""
echo "📦 Your single binary is ready:"
echo "   Location: backend/$BINARY_NAME"
echo ""
echo "🚀 To run the CTI Platform:"
echo "   cd backend"
echo "   ./$BINARY_NAME"
echo ""
echo "🌐 Then open your browser to: http://localhost:8080"
echo ""
print_warning "Note: Make sure you have a MySQL database configured before running."
print_warning "Check backend/config/config.yaml for database settings."
