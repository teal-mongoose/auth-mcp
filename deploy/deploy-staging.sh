#!/bin/bash
# Deploys the auth-mcp server to staging (STAGING.md): builds its image in Cloud Build and deploys it to
# Cloud Run. Run from Git Bash, after deploy/staging-setup.sh, with `gcloud auth login` as an owner of the
# project.
#
#   deploy/deploy-staging.sh
#
# What's built is the repo as committed (git archive of HEAD), so uncommitted changes and git-ignored files
# such as .env.live and .env.staging never leave this PC. The image is tagged with the commit.
set -euo pipefail

PROJECT=auth-mcp-staging-tm
REGION=us-central1
SERVICE=auth-mcp
RUN_SA=auth-mcp-run@$PROJECT.iam.gserviceaccount.com
BASE_URL=https://auth-staging.healthspaces.io
ROOT=$(cd "$(dirname "$0")/.." && pwd)

# Windows paths for gcloud, which isn't a Git Bash program
native() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }

if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
	echo "note: there are uncommitted changes; they aren't deployed" >&2
fi
sha=$(git -C "$ROOT" rev-parse --short HEAD)
IMAGE=$REGION-docker.pkg.dev/$PROJECT/auth-mcp/server:$sha

SOURCE=$(mktemp -d)
trap 'rm -rf "$SOURCE"' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$SOURCE"

echo "Building $sha ($(git -C "$ROOT" branch --show-current))"
gcloud builds submit "$(native "$SOURCE")" --project "$PROJECT" --region "$REGION" --tag "$IMAGE"

# Settings are in the environment: the server reads no file on Cloud Run. It refuses to start unless the
# project is a test project or the staging one, and the base URL uses https.
gcloud run deploy "$SERVICE" --image "$IMAGE" --project "$PROJECT" --region "$REGION" \
	--service-account "$RUN_SA" --allow-unauthenticated \
	--min-instances 0 --max-instances 2 \
	--set-env-vars "AUTH_MCP_PROJECT_ID=$PROJECT,AUTH_MCP_SERVICE_ACCOUNT=$RUN_SA,AUTH_MCP_BASE_URL=$BASE_URL" \
	--set-secrets "AUTH_MCP_SECRET_STAFF_GOOGLE=google-client-secret:latest"

echo
echo "Deployed $sha. Cloud Run's own address: $(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format 'value(status.url)')"
echo "It only works at $BASE_URL, which Google's OAuth client and the broker's links are set up for."
