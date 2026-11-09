#!/bin/bash
# Runs a command as the teal mongoose Google account, which owns the staging project, through a gcloud
# profile of its own on this PC. This PC's usual gcloud account and its sign-ins are never used or changed.
# Run from Git Bash, in this folder:
#
#   deploy/teal-mongoose.sh gcloud auth login                        once, and you sign in
#   deploy/teal-mongoose.sh gcloud auth application-default login    once, and you sign in
#   deploy/teal-mongoose.sh go run ./cmd/auth-setup -env-file .env.staging save
#
# The staging scripts run themselves through this, so they can't run as anyone else.
#
# gcloud reads its profile from CLOUDSDK_CONFIG. Google's Go libraries ignore that on Windows and read
# %APPDATA%\gcloud, so APPDATA is pointed at the profile too, for this command only.
set -euo pipefail

if [ $# -eq 0 ]; then
	echo "usage: deploy/teal-mongoose.sh <command> [args...]" >&2
	exit 2
fi

if [ -z "${AUTH_MCP_TEAL_MONGOOSE:-}" ]; then
	base="${APPDATA:?run this from Git Bash on Windows}\\teal-mongoose"
	mkdir -p "$(cygpath -u "$base")/gcloud"
	export APPDATA="$base"
	export CLOUDSDK_CONFIG="$base\\gcloud"
	export AUTH_MCP_TEAL_MONGOOSE=1
fi

# Signing in and changing the profile's settings need no account yet. Anything else does, and never a
# healthspaces.com one.
if ! { [ "$1" = gcloud ] && { [ "${2:-}" = auth ] || [ "${2:-}" = config ]; }; }; then
	account=$(gcloud config get account 2>/dev/null || true)
	if [ -z "$account" ]; then
		echo "Not signed in. First: deploy/teal-mongoose.sh gcloud auth login" >&2
		exit 1
	fi
	case "$account" in
	*@healthspaces.com)
		echo "Refusing: the profile is signed in as $account, not the teal mongoose account." >&2
		exit 1
		;;
	esac
fi

exec "$@"
