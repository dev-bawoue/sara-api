#!/bin/bash

# SARA API Deployment Script for Google Cloud Run
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE} SARA API Deployment to Google Cloud Run${NC}"
echo "=================================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED} Google Cloud CLI is not installed${NC}"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED} Docker is not installed${NC}"
    echo "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/"
    exit 1
fi

# Get project ID
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo -e "${YELLOW}  No project set. Please set your project:${NC}"
    echo "gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo -e "${GREEN} Using project: $PROJECT_ID${NC}"

# Enable required APIs
echo -e "${BLUE} Enabling required APIs...${NC}"
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Build and deploy
echo -e "${BLUE}🔨 Building and deploying...${NC}"

# Option 1: Using Cloud Build (Recommended)
echo -e "${YELLOW}Choose deployment method:${NC}"
echo "1) Cloud Build (Recommended - builds in cloud)"
echo "2) Local Docker build + push"
read -p "Enter your choice (1 or 2): " choice

if [ "$choice" = "1" ]; then
    echo -e "${BLUE}🏗️  Using Cloud Build...${NC}"
    gcloud builds submit --config cloudbuild.yaml .
else
    echo -e "${BLUE}🐳 Building locally with Docker...${NC}"
    
    # Build the image
    docker build -t gcr.io/$PROJECT_ID/sara-api:latest .
    
    # Configure Docker for GCR
    gcloud auth configure-docker
    
    # Push the image
    docker push gcr.io/$PROJECT_ID/sara-api:latest
    
    # Deploy to Cloud Run
    gcloud run deploy sara-api \
        --image gcr.io/$PROJECT_ID/sara-api:latest \
        --platform managed \
        --region us-central1 \
        --allow-unauthenticated \
        --port 8080 \
        --memory 1Gi \
        --cpu 1 \
        --max-instances 10
fi

echo -e "${GREEN}🎉 Deployment complete!${NC}"

# Get the service URL
SERVICE_URL=$(gcloud run services describe sara-api --platform managed --region us-central1 --format 'value(status.url)')
echo -e "${GREEN}🌐 Your API is available at: $SERVICE_URL${NC}"

echo -e "${BLUE}📋 Next steps:${NC}"
echo "1. Set your environment variables in Cloud Run console"
echo "2. Configure your database connection"
echo "3. Test your API at: $SERVICE_URL/health"
echo "4. View logs: gcloud logs read --service sara-api"