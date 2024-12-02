#! /bin/bash

set -e

# Checks a version tag and performs validation, to catch common release
#  tagging issues prior to build via Github Actions.
#
# 1. The version tag should point to the HEAD of the branch.
#     - tools/build-release.sh#67
# 2. The pushed tag should match the branch tag at the HEAD.
# 3. The CHANGELOG.md contains a header entry for the version tag.
# 4. The CHANGELOG.md entry for that version tag can be parsed for a date.

for arg; do
    case "$arg" in
    --version=*)
	    VERSION=${arg#*=}
        ;;
	--help)
	    echo "Usage: [--version=<ver>]"
	    exit 0
	    ;;
	*)
	    echo "Unknown arg $arg" >&2
	    exit 1
	    ;;
    esac
    shift
done

echo "VERSION: ${VERSION}"

# Version is required.
if [ "$VERSION" = "" ]; then
    echo "The --version argument is required."
    exit 1
fi

# A tag should point to the HEAD of the branch.
HEAD_VERSION=$(git tag --points-at HEAD)
if [ "$HEAD_VERSION" = "" ]; then
    echo "No tagged version at HEAD?" >&2
    exit 1
fi

# The version tag should match the branch tag at the HEAD.
if [ "$HEAD_VERSION" != "$VERSION" ]; then
    echo "The HEAD tag must match the version tag." >&2
    exit 1
fi

# The version tag should match the `make version` target output.
MAKE_VERSION=$(make version)
echo "MAKE_VERSION=$MAKE_VERSION"
if [ "$MAKE_VERSION" != "$VERSION" ]; then
    echo "The version tag must match the \`make version\` target output." >&2
    exit 1
fi

# The CHANGELOG.md contains a header entry for the version tag.
CHANGELOG_TITLE=$(grep "## \[${VERSION#v}\]" CHANGELOG.md)
if [ "$CHANGELOG_TITLE" = "" ]; then
    echo "No entry in the CHANGELOG.md found for $VERSION." >&2
    exit 1
fi
echo "CHANGELOG_TITLE=$CHANGELOG_TITLE"

# The CHANGELOG.md entry for that version tag can be parsed for a date.
RELEASE_DATE=$(sed -n "s/^## \\[.*${VERSION#v}\\] - \\([-0-9]*\\).*/\\1/p" < CHANGELOG.md)
echo "RELEASE_DATE=$RELEASE_DATE"
if [ "$RELEASE_DATE" = "" ]; then
    echo "The release title in CHANGELOG.md cannot be parsed for a date." >&2
    exit 1
fi
