#!/bin/bash

# Quick permission fix for SARA API deployment

PROJECT_ID="precise-equator-274319"

echo "Fixing permissions for SARA API deployment..."

# Get current user
USER_EMAIL=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
echo "Current user: $USER_EMAIL"

# Set project
gcloud config set project $PROJECT_ID

# Add owner role (this gives all necessary permissions)
echo "Adding owner role..."
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="user:$USER_EMAIL" \
    --role="roles/owner" \
    --quiet

# Enable required APIs
echo "Enabling required APIs..."
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable serviceusage.googleapis.com

# Wait for propagation
echo "Waiting 30 seconds for permissions to propagate..."
sleep 30

# Test permissions
echo "Testing permissions..."
if gcloud builds list --limit=1 >/dev/null 2>&1; then
    echo "SUCCESS: Cloud Build permissions working"
else
    echo "WARNING: Cloud Build permissions still not working"
fi

if gcloud artifacts repositories list --location=us-east1 >/dev/null 2>&1; then
    echo "SUCCESS: Artifact Registry permissions working"
else
    echo "WARNING: Artifact Registry permissions still not working"
fi

echo "Permission setup completed!"
echo "You can now run: ./deploy_sara.sh"
