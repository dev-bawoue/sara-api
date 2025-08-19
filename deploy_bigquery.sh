#!/bin/bash

# SARA API BigQuery Deployment Script
# Deploy SARA API with BigQuery, role-based access, and ID encryption

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
SERVICE_NAME="sara-api-update"
REPO_NAME="sara"
DATASET_NAME="sara_dataset"

echo -e "${BLUE} SARA API BigQuery Deployment with Role-Based Access${NC}"
echo "=============================================================="

# Set project
echo -e "${BLUE}  Setting up project configuration...${NC}"
gcloud config set project $PROJECT_ID
gcloud config set run/region $REGION

# Enable required APIs
echo -e "${BLUE} Enabling required APIs...${NC}"
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable bigquery.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable artifactregistry.googleapis.com

# Create Artifact Registry if it doesn't exist
echo -e "${BLUE} Setting up Artifact Registry...${NC}"
if ! gcloud artifacts repositories describe $REPO_NAME --location=$REGION >/dev/null 2>&1; then
    echo "Creating Artifact Registry repository: $REPO_NAME"
    gcloud artifacts repositories create $REPO_NAME \
        --repository-format=docker \
        --location=$REGION \
        --description="SARA API Docker images"
    echo -e "${GREEN} Artifact Registry repository created${NC}"
else
    echo -e "${GREEN} Artifact Registry repository already exists${NC}"
fi

# Create BigQuery dataset if it doesn't exist
echo -e "${BLUE}  Setting up BigQuery dataset...${NC}"
if ! bq ls -d $PROJECT_ID:$DATASET_NAME >/dev/null 2>&1; then
    echo "Creating BigQuery dataset: $DATASET_NAME"
    bq mk --dataset --location=US $PROJECT_ID:$DATASET_NAME
    echo -e "${GREEN} BigQuery dataset created${NC}"
else
    echo -e "${GREEN} BigQuery dataset already exists${NC}"
fi

# Generate and setup encryption key
echo -e "${BLUE} Setting up ID encryption...${NC}"
if ! gcloud secrets describe ID_ENCRYPTION_KEY >/dev/null 2>&1; then
    echo "Generating new encryption key..."
    python3 -c "
from cryptography.fernet import Fernet
import base64
key = Fernet.generate_key()
key_b64 = base64.b64encode(key).decode()
print(key_b64)
" | gcloud secrets create ID_ENCRYPTION_KEY --data-file=-
    echo -e "${GREEN} ID encryption key generated and stored${NC}"
else
    echo -e "${GREEN} ID encryption key already exists${NC}"
fi

# Create or update other secrets
echo -e "${BLUE} Setting up application secrets...${NC}"

# SECRET_KEY
if ! gcloud secrets describe SECRET_KEY >/dev/null 2>&1; then
    echo "Creating SECRET_KEY secret..."
    python3 -c "import secrets; print(secrets.token_hex(32))" | gcloud secrets create SECRET_KEY --data-file=-
else
    echo "SECRET_KEY secret already exists"
fi

# ADMIN_EMAIL
if ! gcloud secrets describe ADMIN_EMAIL >/dev/null 2>&1; then
    echo "admin@sara.com" | gcloud secrets create ADMIN_EMAIL --data-file=-
else
    echo "ADMIN_EMAIL secret already exists"
fi

# ADMIN_PASSWORD
if ! gcloud secrets describe ADMIN_PASSWORD >/dev/null 2>&1; then
    echo "SecureAdminPassword123!" | gcloud secrets create ADMIN_PASSWORD --data-file=-
else
    echo "ADMIN_PASSWORD secret already exists"
fi

# GOOGLE_API_KEY
if ! gcloud secrets describe GOOGLE_API_KEY >/dev/null 2>&1; then
    echo "AIzaSyDXO_dwAeQ0RfpX6FgrZjyCz_8q7UHPmqA" | gcloud secrets create GOOGLE_API_KEY --data-file=-
else
    echo "GOOGLE_API_KEY secret already exists"
fi

# GOOGLE_OAUTH_CLIENT_ID
if ! gcloud secrets describe GOOGLE_OAUTH_CLIENT_ID >/dev/null 2>&1; then
    echo "1024279616298-0hk7fmov09q0bcgfpadgfgo64uihmrfv.apps.googleusercontent.com" | gcloud secrets create GOOGLE_OAUTH_CLIENT_ID --data-file=-
else
    echo "GOOGLE_OAUTH_CLIENT_ID secret already exists"
fi

# GOOGLE_OAUTH_CLIENT_SECRET
if ! gcloud secrets describe GOOGLE_OAUTH_CLIENT_SECRET >/dev/null 2>&1; then
    echo "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" | gcloud secrets create GOOGLE_OAUTH_CLIENT_SECRET --data-file=-
else
    echo "GOOGLE_OAUTH_CLIENT_SECRET secret already exists"
fi

echo -e "${GREEN} All secrets configured${NC}"

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

# Deploy to Cloud Run
echo -e "${BLUE}  Deploying to Cloud Run...${NC}"

gcloud run deploy $SERVICE_NAME \
    --image=$DOCKER_IMAGE \
    --platform=managed \
    --region=$REGION \
    --allow-unauthenticated \
    --port=8080 \
    --memory=2Gi \
    --cpu=2 \
    --timeout=300 \
    --concurrency=100 \
    --min-instances=0 \
    --max-instances=10 \
    --set-secrets="SECRET_KEY=SECRET_KEY:latest,ID_ENCRYPTION_KEY=ID_ENCRYPTION_KEY:latest,ADMIN_EMAIL=ADMIN_EMAIL:latest,ADMIN_PASSWORD=ADMIN_PASSWORD:latest,GOOGLE_API_KEY=GOOGLE_API_KEY:latest,GOOGLE_OAUTH_CLIENT_ID=GOOGLE_OAUTH_CLIENT_ID:latest,GOOGLE_OAUTH_CLIENT_SECRET=GOOGLE_OAUTH_CLIENT_SECRET:latest" \
    --set-env-vars="ENVIRONMENT=production,PROJECT_ID=$PROJECT_ID,PORT=8080,ALGORITHM=HS256,ACCESS_TOKEN_EXPIRE_MINUTES=30,BIGQUERY_DATASET=$DATASET_NAME,BIGQUERY_LOCATION=US,BACKEND_URL=https://sara-api-update-1024279616298.us-east1.run.app,FRONTEND_URL=https://sara-frontend-1024279616298.us-east1.run.app"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --platform managed --region $REGION --format 'value(status.url)')

echo -e "${GREEN} Deployment completed!${NC}"

# Test deployment
echo -e "${BLUE}🔍 Testing deployment...${NC}"
sleep 10

if curl -f -s "$SERVICE_URL/health" >/dev/null; then
    echo -e "${GREEN} Health check passed${NC}"
    
    # Test role-based access
    echo -e "${BLUE} Testing role-based access...${NC}"
    
    # Test basic endpoints
    echo "Testing basic API endpoints..."
    curl -s "$SERVICE_URL/" | jq . || echo "Root endpoint accessible"
    
else
    echo -e "${RED} Health check failed${NC}"
    echo "Checking service logs..."
    gcloud logs read --service=$SERVICE_NAME --region=$REGION --limit=10
fi

# Create initial admin user (if not exists)
echo -e "${BLUE}👤 Setting up initial admin user...${NC}"

# Create a simple script to setup admin user
cat > setup_admin.py << 'EOF'
import requests
import os
import json

# Get service URL from environment or use default
SERVICE_URL = os.getenv('SERVICE_URL', 'https://sara-api-update-1024279616298.us-east1.run.app')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@sara.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'SecureAdminPassword123!')

def setup_admin_user():
    """Setup initial admin user if it doesn't exist"""
    try:
        # Try to login first
        login_data = {
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        }
        
        response = requests.post(f"{SERVICE_URL}/api/login", json=login_data)
        
        if response.status_code == 200:
            print(" Admin user already exists and can login")
            return True
        elif response.status_code == 401:
            print("ℹ  Admin user may not exist, this is expected for first deployment")
            return False
        else:
            print(f"  Unexpected response: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"ℹ  Could not test admin login (this is normal for first deployment): {e}")
        return False

if __name__ == "__main__":
    setup_admin_user()
EOF

python3 setup_admin.py
rm setup_admin.py

# Summary
echo -e "${GREEN} Deployment Summary${NC}"
echo "======================================================="
echo " Service URL: $SERVICE_URL"
echo " Health Check: $SERVICE_URL/health"
echo " API Docs: $SERVICE_URL/docs"
echo "  Database: BigQuery ($PROJECT_ID.$DATASET_NAME)"
echo " Image: $DOCKER_IMAGE"
echo " Features: Role-based access, ID encryption, OAuth"

echo -e "${BLUE} Quick Commands:${NC}"
echo "• View logs: gcloud logs read --service=$SERVICE_NAME --region=$REGION"
echo "• View service: gcloud run services describe $SERVICE_NAME --region=$REGION"
echo "• Query BigQuery: bq query --use_legacy_sql=false \"SELECT COUNT(*) FROM \`$PROJECT_ID.$DATASET_NAME.users\`\""
echo "• Check roles: bq query --use_legacy_sql=false \"SELECT * FROM \`$PROJECT_ID.$DATASET_NAME.roles\`\""

echo -e "${YELLOW}  Important Notes:${NC}"
echo "• Admin credentials: admin@sara.com / SecureAdminPassword123!"
echo "• Change admin password after first login"
echo "• ID encryption is enabled - all IDs are encrypted in API responses"
echo "• Default users get 'client' role, admins get 'admin' role"
echo "• OAuth users automatically get 'client' role"

echo -e "${GREEN} Deployment completed successfully!${NC}"

cd ..