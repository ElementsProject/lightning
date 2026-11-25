#! /bin/sh
# Usage: verify-release-tarball.sh <keys-dir> <SHA256SUMS> <tarball> [min-signatures]
#
# Succeeds when <SHA256SUMS>.asc has >= min-signatures (default 1) good
# signatures from the *.txt keys in <keys-dir> and no bad one, and the
# tarball matches its line in <SHA256SUMS>.  gpg's exit status is useless
# here: it fails whenever any co-signer's key is unknown, so we read its
# status lines instead.
set -e

KEYS=${1:-}
SUMS=${2:-}
TARBALL=${3:-}
MIN=${4:-1}
if [ -z "$KEYS" ] || [ -z "$SUMS" ] || [ -z "$TARBALL" ]; then
    echo "Usage: $0 <keys-dir> <SHA256SUMS-file> <tarball> [min-signatures]" >&2
    exit 1
fi
[ -f "$SUMS.asc" ] || { echo "$SUMS.asc: no such file" >&2; exit 1; }
[ -f "$TARBALL" ] || { echo "$TARBALL: no such file" >&2; exit 1; }

# Private keyring: only $KEYS can vouch, and the caller's is untouched.
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
STATUS=$(mktemp)
trap 'rm -rf "$GNUPGHOME" "$STATUS"' EXIT

gpg --quiet --batch --import "$KEYS"/*.txt

# Name the manifest explicitly, or an inline-signed .asc would verify
# its own payload instead.  Exit status ignored, see above.
gpg --status-fd 3 --verify "$SUMS.asc" "$SUMS" 3>"$STATUS" || true

if grep -q '^\[GNUPG:\] BADSIG ' "$STATUS"; then
    echo "$SUMS.asc: a signature does not match $SUMS" >&2
    exit 1
fi
GOOD=$(grep -c '^\[GNUPG:\] VALIDSIG ' "$STATUS" || true)
if [ "$GOOD" -lt "$MIN" ]; then
    echo "$SUMS.asc: $GOOD good signature(s) from keys in $KEYS, $MIN required" >&2
    exit 1
fi
echo "$SUMS.asc: $GOOD good signature(s) from keys in $KEYS"

# The tarball's own line: --ignore-missing would pass if it were unlisted.
NAME=$(basename "$TARBALL")
LINE=$(grep "  $NAME\$" "$SUMS") || {
    echo "$NAME is not listed in $SUMS" >&2
    exit 1
}
(cd "$(dirname "$TARBALL")" && echo "$LINE" | sha256sum -c -)
