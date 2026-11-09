#!/bin/bash
# One-time setup of the staging project for deploys (STAGING.md). Safe to run again: it creates only
# what's missing and re-applies the same roles. Needs `gcloud auth login` as an owner of the project, and
# Firestore already created. It never sees the client secret: that's added by hand in the console.
#
#   deploy/staging-setup.sh
#
# Set AUTH_MCP_STAGING_PROJECT if the project's id isn't auth-mcp-staging.
set -euo pipefail

PROJECT=${AUTH_MCP_STAGING_PROJECT:-auth-mcp-staging}
REGION=us-central1
REPO=auth-mcp
RUN_SA=auth-mcp-run@$PROJECT.iam.gserviceaccount.com
SECRET=google-client-secret

gc() { gcloud --project "$PROJECT" --quiet "$@"; }

# A new service account can take a minute or two to be usable in a policy, so bindings are retried.
bind() {
	local try
	for try in 1 2 3 4 5 6 7 8 9 10 11 12; do
		gc "$@" >/dev/null 2>&1 && return 0
		[ "$try" -eq 1 ] && echo "  waiting for the new service account to be usable..."
		sleep 10
	done
	gc "$@" >/dev/null
}

echo "APIs"
gc services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
	secretmanager.googleapis.com iamcredentials.googleapis.com identitytoolkit.googleapis.com \
	firestore.googleapis.com

echo "Artifact Registry repository $REPO"
gc artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 ||
	gc artifacts repositories create "$REPO" --repository-format docker --location "$REGION" \
		--description "auth-mcp images"

echo "The server's service account, $RUN_SA"
gc iam service-accounts describe "$RUN_SA" >/dev/null 2>&1 ||
	gc iam service-accounts create auth-mcp-run --display-name "auth-mcp server (Cloud Run)"
# Firestore, Firebase Auth, and counting its own calls against this project
for role in roles/datastore.user roles/firebaseauth.admin roles/serviceusage.serviceUsageConsumer; do
	bind projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$RUN_SA" --role "$role" \
		--condition None
done
# Signing custom tokens as itself, with no key file
bind iam service-accounts add-iam-policy-binding "$RUN_SA" --member "serviceAccount:$RUN_SA" \
	--role roles/iam.serviceAccountTokenCreator

# Cloud Build runs as the project's Compute Engine default service account
NUMBER=$(gc projects describe "$PROJECT" --format 'value(projectNumber)')
BUILD_SA=$NUMBER-compute@developer.gserviceaccount.com
echo "Cloud Build's service account, $BUILD_SA"
for role in roles/artifactregistry.writer roles/logging.logWriter roles/storage.objectViewer; do
	bind projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$BUILD_SA" --role "$role" \
		--condition None
done

echo "Expiring abandoned sign-ins and codes in Firestore"
for group in pending_signins codes; do
	gc firestore fields ttls update expires_at --collection-group "$group" --enable-ttl --async >/dev/null
done

echo "Secret $SECRET"
gc secrets describe "$SECRET" >/dev/null 2>&1 ||
	gc secrets create "$SECRET" --replication-policy automatic >/dev/null
# Only this secret, rather than every secret in the project
bind secrets add-iam-policy-binding "$SECRET" --member "serviceAccount:$RUN_SA" \
	--role roles/secretmanager.secretAccessor

echo
if [ -z "$(gc secrets versions list "$SECRET" --filter 'state=ENABLED' --format 'value(name)' --limit 1)" ]; then
	echo "Add the Google OAuth client's secret as a new version of $SECRET in the console:"
	echo "  https://console.cloud.google.com/security/secret-manager/secret/$SECRET/versions?project=$PROJECT"
else
	echo "The secret has a value. Next: deploy/deploy-staging.sh"
fi
