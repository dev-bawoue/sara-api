#!/bin/bash

# Complete Build and Push Process for SARA API
# Execute these commands in order

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration (matching your deployment script)
PROJECT_ID="precise-equator-274319"
REGION="us-east1"
SERVICE_NAME="sara-api"
REPO_NAME="sara"

echo -e "${BLUE}SARA API - Build and Push Process${NC}"
echo "===================================="

# Step 1: Set project configuration
echo -e "${BLUE}Step 1: Setting project configuration...${NC}"
gcloud config set project $PROJECT_ID
gcloud config set run/region $REGION

# Step 2: Configure Docker authentication
echo -e "${BLUE}Step 2: Configuring Docker authentication...${NC}"
gcloud auth configure-docker ${REGION}-docker.pkg.dev

# Step 3: Create Artifact Registry repository (if it doesn't exist)
echo -e "${BLUE}Step 3: Creating/Checking Artifact Registry repository...${NC}"
if ! gcloud artifacts repositories describe $REPO_NAME --location=$REGION >/dev/null 2>&1; then
    echo "Creating Artifact Registry repository: $REPO_NAME"
    gcloud artifacts repositories create $REPO_NAME \
        --repository-format=docker \
        --location=$REGION \
        --description="SARA API Docker images"
    echo -e "${GREEN}Repository created${NC}"
else
    echo -e "${GREEN}Repository already exists${NC}"
fi

# Step 4: Build Docker image locally
echo -e "${BLUE}Step 4: Building Docker image locally...${NC}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DOCKER_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$SERVICE_NAME:$TIMESTAMP"
DOCKER_IMAGE_LATEST="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$SERVICE_NAME:latest"

echo "Building images:"
echo "  - $DOCKER_IMAGE"
echo "  - $DOCKER_IMAGE_LATEST"

if docker build -t $DOCKER_IMAGE -t $DOCKER_IMAGE_LATEST .; then
    echo -e "${GREEN}Docker images built successfully${NC}"
else
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi

# Step 5: Push Docker images
echo -e "${BLUE}Step 5: Pushing Docker images...${NC}"

echo "Pushing timestamped image..."
if docker push $DOCKER_IMAGE; then
    echo -e "${GREEN}Timestamped image pushed successfully${NC}"
else
    echo -e "${RED}Failed to push timestamped image${NC}"
    exit 1
fi

echo "Pushing latest image..."
if docker push $DOCKER_IMAGE_LATEST; then
    echo -e "${GREEN}Latest image pushed successfully${NC}"
else
    echo -e "${RED}Failed to push latest image${NC}"
    exit 1
fi

# Step 6: Verify images in registry
echo -e "${BLUE}Step 6: Verifying images in Artifact Registry...${NC}"
if gcloud artifacts docker images list ${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO_NAME}/${SERVICE_NAME} --limit=5; then
    echo -e "${GREEN}Images verified in registry${NC}"
else
    echo -e "${YELLOW}Could not list images (permission issue), but push likely succeeded${NC}"
fi

echo -e "${GREEN}Build and Push Process Completed!${NC}"
echo "============================================"
echo ""
echo "Images available:"
echo "  - $DOCKER_IMAGE"
echo "  - $DOCKER_IMAGE_LATEST"
echo ""
echo "Next steps:"
echo "1. You can now run your deployment script: ./deploy_sara.sh"
echo "2. Or deploy manually with:"
echo "   gcloud run deploy $SERVICE_NAME --image=$DOCKER_IMAGE --region=$REGION"
echo ""
echo "Image URLs for reference:"
echo "  Timestamped: $DOCKER_IMAGE"
echo "  Latest: $DOCKER_IMAGE_LATEST" 