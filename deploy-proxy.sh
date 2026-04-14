#!/bin/bash
# Deploy Claude Subscription Proxy to Cloud Run
# Usage: ./deploy-proxy.sh

set -e

PROJECT="clientele-465208"
REGION="us-central1"
SERVICE="claude-proxy"
IMAGE="gcr.io/$PROJECT/$SERVICE"

echo "==> Building image..."
gcloud builds submit --tag "$IMAGE" --project "$PROJECT" .

echo "==> Deploying to Cloud Run..."
gcloud run deploy "$SERVICE" \
  --image "$IMAGE" \
  --platform managed \
  --region "$REGION" \
  --project "$PROJECT" \
  --port 3099 \
  --memory 256Mi \
  --cpu 1 \
  --min-instances 1 \
  --max-instances 2 \
  --no-allow-unauthenticated \
  --set-env-vars "PROXY_PORT=3099,GCLOUD_PROJECT=${PROJECT},SMARTASSIST_URL=https://smartassist-web-880013595324.us-central1.run.app" \
  --set-secrets "CLAUDE_ACCESS_TOKEN=claude-access-token:latest,CLAUDE_REFRESH_TOKEN=claude-refresh-token:latest,CLAUDE_TOKEN_EXPIRES_AT=claude-token-expires:latest,OPENAI_API_KEY=openai-api-key:latest,SMARTASSIST_INTERNAL_SECRET=internal-auth-token:latest"

echo ""
echo "==> Done! Get the service URL:"
URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" --format "value(status.url)")
echo "  $URL"
echo ""
echo "==> Set in SmartAssist .env.production.yaml:"
echo "  CLAUDE_PROXY_URL: \"$URL/v1\""
echo ""
echo "==> Don't forget to create secrets:"
echo "  echo -n 'YOUR_ACCESS_TOKEN' | gcloud secrets create claude-access-token --data-file=- --project $PROJECT"
echo "  echo -n 'YOUR_REFRESH_TOKEN' | gcloud secrets create claude-refresh-token --data-file=- --project $PROJECT"
echo "  echo -n 'EXPIRY_TIMESTAMP' | gcloud secrets create claude-token-expires --data-file=- --project $PROJECT"
