#!/bin/bash
# Script to create a new ReadMe version when a new release tag is pushed.
# Usage: create-readme-version.sh <version_from_file>
#
# The version_from_file should be like "26.06.2" (without the v prefix).
# The script reads the .version file, determines the ReadMe version name,
# and creates it if it doesn't exist.

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  # Try reading from .version file
  if [ -f .version ]; then
    FULL_VERSION=$(cat .version | tr -d ' \n')
    VERSION="${FULL_VERSION#v}"
  else
    echo "❌ No version provided and no .version file found."
    exit 1
  fi
fi

# Strip 'v' prefix if present
VERSION="${VERSION#v}"

if [ -z "$VERSION" ]; then
  echo "❌ Could not determine version."
  exit 1
fi

echo "📋 Version from .version file: v${VERSION}"

# Determine the short version (e.g., "26.06" from "26.06.2")
SHORT_VERSION=$(echo "$VERSION" | grep -oE '^[0-9]+\.[0-9]+')
echo "📋 Short version for ReadMe: ${SHORT_VERSION}"

# Check for RC releases
IS_RC=false
if echo "$VERSION" | grep -qi "rc"; then
  IS_RC=true
  echo "📋 This is a Release Candidate"
fi

# The ReadMe API key is required
README_API_KEY="${README_API_KEY:-}"
if [ -z "$README_API_KEY" ]; then
  echo "❌ README_API_KEY environment variable not set."
  exit 1
fi

# Check if a version/branch already exists in ReadMe
echo "🔍 Checking if version '${SHORT_VERSION}' exists in ReadMe..."

EXISTING_VERSIONS=$(curl -s -X GET "https://api.readme.com/v2/branches" \
  -H "Authorization: Bearer ${README_API_KEY}")

VERSION_EXISTS=$(echo "$EXISTING_VERSIONS" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    versions = []
    for item in data.get('data', []):
        versions.append(item.get('name', ''))
    if '${SHORT_VERSION}' in versions:
        print('true')
    else:
        print('false')
except:
    print('false')
")

if [ "$VERSION_EXISTS" = "true" ]; then
  echo "✅ Version '${SHORT_VERSION}' already exists in ReadMe. Skipping creation."
  echo "readme_version_exists=true" >> "$GITHUB_OUTPUT"
  echo "readme_version=${SHORT_VERSION}" >> "$GITHUB_OUTPUT"
  echo "readme_version_created=false" >> "$GITHUB_OUTPUT"
  exit 0
fi

echo "🆕 Creating new ReadMe version '${SHORT_VERSION}'..."

# Determine which version to fork from
# Try to find the most recent stable version in the same major.minor series
FORK_VERSION="stable"
echo "🔍 Looking for a base version to fork from..."

# Find the latest existing version in ReadMe as potential base
BASE_VERSION=$(echo "$EXISTING_VERSIONS" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    names = []
    for item in data.get('data', []):
        name = item.get('name', '')
        # Prefer non-'master' versions as base
        if name and 'master' not in name:
            names.append(name)
    # Get the last one (assuming sorted order)
    if names:
        print(names[-1])
    else:
        print('')
except:
    print('')
")

if [ -n "$BASE_VERSION" ] && [ "$BASE_VERSION" != "$SHORT_VERSION" ]; then
  FORK_VERSION="$BASE_VERSION"
fi

echo "📋 Forking from version: '${FORK_VERSION}'"

# Create the new version via ReadMe API
# POST /v2/versions
CREATE_RESPONSE=$(curl -s -X POST "https://api.readme.com/v2/versions" \
  -H "Authorization: Bearer ${README_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"version\": \"${SHORT_VERSION}\",
    \"version_clean\": \"${SHORT_VERSION}\",
    \"fork\": \"${FORK_VERSION}\",
    \"is_stable\": false,
    \"is_beta\": ${IS_RC},
    \"is_deprecated\": false
  }")

echo "📋 Create response: $CREATE_RESPONSE"

# Check if creation succeeded
CREATE_STATUS=$(echo "$CREATE_RESPONSE" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if 'version' in data:
        print('success')
    else:
        print('failed:', data.get('error', 'unknown error'))
except Exception as e:
    print('parse error:', str(e))
")

if echo "$CREATE_STATUS" | grep -q "success"; then
  echo "✅ Successfully created ReadMe version '${SHORT_VERSION}'"
  echo "readme_version_exists=false" >> "$GITHUB_OUTPUT"
  echo "readme_version=${SHORT_VERSION}" >> "$GITHUB_OUTPUT"
  echo "readme_version_created=true" >> "$GITHUB_OUTPUT"
else
  echo "❌ Failed to create ReadMe version: $CREATE_STATUS"
  echo "readme_version_exists=false" >> "$GITHUB_OUTPUT"
  echo "readme_version=${SHORT_VERSION}" >> "$GITHUB_OUTPUT"
  echo "readme_version_created=false" >> "$GITHUB_OUTPUT"
  exit 1
fi
