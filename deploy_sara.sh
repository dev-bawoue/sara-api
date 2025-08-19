#!/bin/bash

# SARA API Simple Deployment Script
# Pour déployer rapidement quand tout est déjà configuré

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

echo -e "${BLUE} SARA API Quick Deployment${NC}"
echo "================================"

# Set project
gcloud config set project $PROJECT_ID
gcloud config set run/region $REGION

# Clone/update repository
echo -e "${BLUE} Getting source code...${NC}"
if [ ! -d "sara-api" ]; then
    git clone https://github.com/dev-bawoue/sara-api.git
    cd sara-api
else
    cd sara-api
    git pull origin main
fi

# Build and push Docker image
echo -e "${BLUE} Building Docker image...${NC}"
DOCKER_IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/sara-api:$(date +%Y%m%d-%H%M%S)"
DOCKER_IMAGE_LATEST="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/sara-api:latest"

gcloud builds submit --tag $DOCKER_IMAGE --tag $DOCKER_IMAGE_LATEST .

echo -e "${GREEN} Docker image built successfully${NC}"

# Get Cloud SQL connection name
CONNECTION_NAME=$(gcloud sql instances describe $CLOUD_SQL_INSTANCE --format="value(connectionName)")

# Deploy to Cloud Run
echo -e "${BLUE} Deploying to Cloud Run...${NC}"

gcloud run deploy $SERVICE_NAME \
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
    --set-env-vars="ENVIRONMENT=production,PROJECT_ID=$PROJECT_ID,PORT=8080,ALGORITHM=HS256,ACCESS_TOKEN_EXPIRE_MINUTES=30"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format 'value(status.url)')

echo -e "${GREEN} Deployment completed!${NC}"

# Run migrations if migration script exists
if [ -f "migrate_cloud.py" ]; then
    echo -e "${BLUE} Running database migrations...${NC}"
    
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
    gcloud run jobs execute $SERVICE_NAME-migration --region=$REGION --wait
    echo -e "${GREEN} Database migrations completed${NC}"
fi

# Test deployment
echo -e "${BLUE}🔍 Testing deployment...${NC}"
sleep 5

if curl -f -s "$SERVICE_URL/health" >/dev/null; then
    echo -e "${GREEN} Health check passed${NC}"
else
    echo -e "${YELLOW} Health check failed, checking logs...${NC}"
    gcloud logs read --service=$SERVICE_NAME --region=$REGION --limit=10
fi

# Summary
echo -e "${GREEN} Deployment Summary${NC}"
echo "====================="
echo "• Service URL: $SERVICE_URL"
echo "• Health Check: $SERVICE_URL/health"
echo "• API Docs: $SERVICE_URL/docs"
echo "• Image: $DOCKER_IMAGE"

echo -e "${BLUE} Quick Commands:${NC}"
echo "• View logs: gcloud logs read --service=$SERVICE_NAME --region=$REGION"
echo "• View service: gcloud run services describe $SERVICE_NAME --region=$REGION"

cd ..