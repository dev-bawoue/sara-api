#!/bin/bash

# SARA API Simple Deployment Script
# Pour deployer rapidement quand tout est deja configure

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PROJECT_ID="precise-equator-274319"
REGION="us-east1"
SERVICE_NAME="sara-api"
REPO_NAME="sara"
CLOUD_SQL_INSTANCE="sara-postgres"

# Function to check permissions
check_permissions() {
    echo -e "${BLUE}Checking permissions...${NC}"
    
    local has_errors=false
    
    # Test Cloud Build
    if ! gcloud builds list --limit=1 >/dev/null 2>&1; then
        echo -e "${RED}Missing Cloud Build permissions${NC}"
        has_errors=true
    fi
    
    # Test Artifact Registry
    if ! gcloud artifacts repositories list --location=$REGION >/dev/null 2>&1; then
        echo -e "${RED}Missing Artifact Registry permissions${NC}"
        has_errors=true
    fi
    
    # Test Secret Manager
    if ! gcloud secrets list --limit=1 >/dev/null 2>&1; then
        echo -e "${RED}Missing Secret Manager permissions${NC}"
        has_errors=true
    fi
    
    if [ "$has_errors" = true ]; then
        echo -e "${RED}Permission issues detected.${NC}"
        echo -e "${YELLOW}Run this command first: chmod +x fix_permissions.sh && ./fix_permissions.sh${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}All required permissions verified${NC}"
}

echo -e "${BLUE}SARA API Quick Deployment${NC}"
echo "================================"

# Set project
echo -e "${BLUE}Setting project configuration...${NC}"
gcloud config set project $PROJECT_ID
gcloud config set run/region $REGION

# Check permissions before proceeding
check_permissions

# Check if Artifact Registry exists
echo -e "${BLUE}Checking Artifact Registry...${NC}"
if ! gcloud artifacts repositories describe $REPO_NAME --location=$REGION >/dev/null 2>&1; then
    echo "Creating Artifact Registry repository: $REPO_NAME"
    gcloud artifacts repositories create $REPO_NAME \
        --repository-format=docker \
        --location=$REGION \
        --description="SARA API Docker images"
    echo -e "${GREEN}Artifact Registry repository created${NC}"
else
    echo -e "${GREEN}Artifact Registry repository already exists${NC}"
fi

# Clone/update repository
echo -e "${BLUE}Getting source code...${NC}"
if [ ! -d "sara-api" ]; then
    if git clone https://github.com/dev-bawoue/sara-api.git; then
        echo -e "${GREEN}Repository cloned successfully${NC}"
        cd sara-api
    else
        echo -e "${RED}Failed to clone repository${NC}"
        exit 1
    fi
else
    cd sara-api
    if git pull origin main; then
        echo -e "${GREEN}Repository updated successfully${NC}"
    else
        echo -e "${YELLOW}Git pull failed, continuing with existing code${NC}"
    fi
fi

# Build and push Docker image
echo -e "${BLUE}Building Docker image...${NC}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DOCKER_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/sara-api:$TIMESTAMP"
DOCKER_IMAGE_LATEST="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/sara-api:latest"

if gcloud builds submit --tag $DOCKER_IMAGE --tag $DOCKER_IMAGE_LATEST .; then
    echo -e "${GREEN}Docker image built successfully${NC}"
else
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi

# Check if Cloud SQL instance exists
echo -e "${BLUE}Checking Cloud SQL instance...${NC}"
if gcloud sql instances describe $CLOUD_SQL_INSTANCE >/dev/null 2>&1; then
    CONNECTION_NAME=$(gcloud sql instances describe $CLOUD_SQL_INSTANCE --format="value(connectionName)")
    echo -e "${GREEN}Cloud SQL instance found: $CONNECTION_NAME${NC}"
else
    echo -e "${RED}Cloud SQL instance '$CLOUD_SQL_INSTANCE' not found${NC}"
    echo "Please create the Cloud SQL instance first or update the CLOUD_SQL_INSTANCE variable"
    exit 1
fi

# Deploy to Cloud Run
echo -e "${BLUE}Deploying to Cloud Run...${NC}"

if gcloud run deploy $SERVICE_NAME \
    --image=$DOCKER_IMAGE \
    --platform=managed \
    --region=$REGION \
    --allow-unauthenticated \
    --port=8000 \
    --memory=1Gi \
    --cpu=1 \
    --timeout=300 \
    --concurrency=100 \
    --min-instances=0 \
    --max-instances=10 \
    --add-cloudsql-instances=$CONNECTION_NAME \
    --set-secrets="DATABASE_URL=DATABASE_URL:latest,SECRET_KEY=SECRET_KEY:latest,ADMIN_EMAIL=ADMIN_EMAIL:latest,ADMIN_PASSWORD=ADMIN_PASSWORD:latest,GOOGLE_API_KEY=GOOGLE_API_KEY:latest" \
    --set-env-vars="ENVIRONMENT=production,PROJECT_ID=$PROJECT_ID,PORT=8000,ALGORITHM=HS256,ACCESS_TOKEN_EXPIRE_MINUTES=30"; then
    echo -e "${GREEN}Cloud Run deployment successful${NC}"
else
    echo -e "${RED}Cloud Run deployment failed${NC}"
    exit 1
fi

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format 'value(status.url)')

echo -e "${GREEN}Deployment completed!${NC}"

# Run migrations if migration script exists
if [ -f "migrate_cloud.py" ]; then
    echo -e "${BLUE}Running database migrations...${NC}"
    
    # Update or create migration job
    gcloud run jobs replace <(cat <<EOF
apiVersion: run.googleapis.com/v1
kind: Job
metadata:
  name: $SERVICE_NAME-migration
spec:
  template:
    spec:
      template:
        spec:
          serviceAccountName: sara-api-service@$PROJECT_ID.iam.gserviceaccount.com
          containers:
          - image: $DOCKER_IMAGE
            command: ["python"]
            args: ["migrate_cloud.py"]
            env:
            - name: ENVIRONMENT
              value: production
            - name: PROJECT_ID
              value: $PROJECT_ID
            resources:
              limits:
                cpu: 1000m
                memory: 512Mi
          restartPolicy: OnFailure
          taskTimeoutSeconds: 300
      parallelism: 1
      completions: 1
EOF
) --region=$REGION || echo "Creating new migration job..."

    # Execute migration
    if gcloud run jobs execute $SERVICE_NAME-migration --region=$REGION --wait; then
        echo -e "${GREEN}Database migrations completed${NC}"
    else
        echo -e "${YELLOW}Migration job failed, but deployment may still work${NC}"
    fi
fi

# Test deployment
echo -e "${BLUE}Testing deployment...${NC}"
sleep 10

if curl -f -s "$SERVICE_URL/health" >/dev/null; then
    echo -e "${GREEN}Health check passed${NC}"
    
    # Test basic endpoint
    if curl -s "$SERVICE_URL/" >/dev/null; then
        echo -e "${GREEN}Root endpoint accessible${NC}"
    fi
else
    echo -e "${YELLOW}Health check failed, checking logs...${NC}"
    gcloud logs read --service=$SERVICE_NAME --region=$REGION --limit=10
fi

# Summary
echo ""
echo -e "${GREEN}Deployment Summary${NC}"
echo "====================="
echo "Service URL: $SERVICE_URL"
echo "Health Check: $SERVICE_URL/health"
echo "API Docs: $SERVICE_URL/docs"
echo "Image: $DOCKER_IMAGE"

echo ""
echo -e "${BLUE}Quick Commands:${NC}"
echo "View logs: gcloud logs read --service=$SERVICE_NAME --region=$REGION"
echo "View service: gcloud run services describe $SERVICE_NAME --region=$REGION"

cd ..