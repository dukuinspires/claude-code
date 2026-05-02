#!/bin/bash
# Deploy DeepSeek Proxy to Cloud Run
# Usage: ./deploy-deepseek-proxy.sh
#
# This script builds and deploys the DeepSeek web proxy. It uses --update-env-vars
# (not --set-env-vars) to preserve runtime state like DS_POOL_JSON that gets set
# dynamically via the SmartAssist sync endpoint.
#
# Pool loading order on startup:
#   1. DS_POOL_JSON env var (if set) → immediate pool from tokens
#   2. Always calls SmartAssist /api/webhooks/ds-proxy-sync → merges DB accounts
#      (includes passwords for VPS OAuth relogin on token expiry)
#
# Relogin on token expiry (40003):
#   1. VPS OAuth (primary) — calls VPS /ds-oauth/register with Google password
#   2. Password login (fallback) — direct DeepSeek API (blocked by RISK_DEVICE_DETECTED)

set -e

PROJECT="clientele-465208"
REGION="us-central1"
SERVICE="deepseek-proxy"
REPO="cloud-run-source-deploy"
IMAGE="us-central1-docker.pkg.dev/$PROJECT/$REPO/$SERVICE"
SMARTASSIST_URL="https://smartassist-web-880013595324.us-central1.run.app"
VPS_NODE1="http://192.3.15.37:3080"
VPS_SECRET="sa_smtp_proxy_2026"

echo "==> Building image from Dockerfile.deepseek..."
gcloud builds submit \
  --project "$PROJECT" \
  --config /dev/stdin . <<EOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${IMAGE}', '-f', 'Dockerfile.deepseek', '.']
images:
  - '${IMAGE}'
EOF

echo ""
echo "==> Deploying $SERVICE to Cloud Run..."
# IMPORTANT: --update-env-vars preserves existing vars (like DS_POOL_JSON).
# Never use --set-env-vars here — it wipes everything not listed.
gcloud run deploy "$SERVICE" \
  --image "$IMAGE" \
  --platform managed \
  --region "$REGION" \
  --project "$PROJECT" \
  --port 3098 \
  --memory 512Mi \
  --cpu 1 \
  --timeout 900 \
  --min-instances 1 \
  --max-instances 3 \
  --no-allow-unauthenticated \
  --update-env-vars "DS_PROXY_PORT=3098,SMARTASSIST_URL=${SMARTASSIST_URL},VPS_PROXY_URL=${VPS_NODE1},SMTP_PROXY_SECRET=${VPS_SECRET}" \
  --update-secrets "INTERNAL_AUTH_TOKEN=internal-auth-token:latest,DS_USER_TOKEN=ds-user-token:latest"

echo ""
echo "==> Done! Getting service URL..."
URL=$(gcloud run services describe "$SERVICE" \
  --region "$REGION" \
  --project "$PROJECT" \
  --format "value(status.url)")

echo ""
echo "  Service URL: $URL"
echo "  Pool sync:   Automatic on startup (calls SmartAssist DB)"
echo "  Relogin:     VPS OAuth → password login fallback"
echo ""
echo "==> Verify pool loaded correctly:"
echo "  gcloud logging read 'resource.labels.service_name=\"deepseek-proxy\"' --limit=30 --format='value(textPayload)' | grep -E 'init|sync|pool|loaded'"
