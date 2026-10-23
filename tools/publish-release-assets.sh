#! /bin/sh
# Upload release files to an existing GitHub release without replacing
# anything already published there.
#
# - A file the release does not have yet is uploaded.
# - A file the release already has must be byte-identical, or we stop: a
#   different tarball or SHA256SUMS means the builds disagree, and nothing is
#   touched.
# - A detached signature (.asc) the release already has is merged instead:
#   our signature is appended to the published one, so the signatures that
#   release captains added by hand are kept.  If the published file already
#   carries our signature it is left alone, so re-running is harmless.
#
# Usage: tools/publish-release-assets.sh <tag> <file>...
# Needs gh (with GH_TOKEN) and gpg with the signing key that made our .asc.
set -e

TAG=${1:-}
if [ -z "$TAG" ] || [ $# -lt 2 ]; then
    echo "Usage: $0 <tag> <file>..." >&2
    exit 1
fi
shift

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

gh release view "$TAG" --json assets --jq '.assets[].name' > "$WORK/published"

is_published()
{
    grep -qxF "$1" "$WORK/published"
}

fetch()
{
    rm -f "$WORK/remote"
    gh release download "$TAG" --pattern "$1" --output "$WORK/remote"
}

# The fingerprint of every good signature in $1 over $2, one per line.
good_sigs()
{
    gpg --status-fd 1 --verify "$1" "$2" 2>/dev/null | awk '$2 == "VALIDSIG" {print $3}' || true
}

# Count signature packets, whether or not we have the signer's key.
count_sigs()
{
    gpg --list-packets "$1" 2>/dev/null | grep -c '^:signature packet' || true
}

# Concatenating armored signatures can leave a block gpg only half-reads
# (no blank line after the BEGIN line), and it then silently skips it.
normalise()
{
    awk '/^-----BEGIN PGP SIGNATURE-----$/{print; getline l; if (l != "") print ""; print l; next} {print}' "$1"
}

# Pass 1: everything except signatures.  Stop before any upload if a
# published file differs from ours.
for f; do
    case "$f" in *.asc) continue;; esac
    name=$(basename "$f")
    if is_published "$name"; then
        fetch "$name"
        if ! cmp -s "$f" "$WORK/remote"; then
            echo "$name: published copy differs from ours, refusing to continue" >&2
            exit 1
        fi
    fi
done

for f; do
    case "$f" in *.asc) continue;; esac
    name=$(basename "$f")
    if is_published "$name"; then
        echo "$name: already published, identical"
    else
        echo "$name: uploading"
        gh release upload "$TAG" "$f"
    fi
done

# Pass 2: signatures.  The file each one signs is now the published one.
for f; do
    case "$f" in *.asc) ;; *) continue;; esac
    name=$(basename "$f")
    signed="${f%.asc}"
    [ -f "$signed" ] || { echo "$name: no $signed next to it" >&2; exit 1; }

    ours=$(good_sigs "$f" "$signed")
    [ -n "$ours" ] || { echo "$name: our own signature does not verify" >&2; exit 1; }

    if ! is_published "$name"; then
        echo "$name: uploading"
        gh release upload "$TAG" "$f"
        continue
    fi

    fetch "$name"
    if good_sigs "$WORK/remote" "$signed" | grep -qxF "$ours"; then
        echo "$name: already carries our signature, left alone"
        continue
    fi

    # Count after normalising: that also repairs a block the published file
    # already had that gpg could not read.
    normalise "$WORK/remote" > "$WORK/remote.norm"
    before=$(count_sigs "$WORK/remote.norm")
    mkdir -p "$WORK/merged"
    { cat "$WORK/remote.norm"; normalise "$f"; } > "$WORK/merged/$name"
    after=$(count_sigs "$WORK/merged/$name")
    if [ "$after" -ne $((before + $(count_sigs "$f"))) ]; then
        echo "$name: merged file has $after signatures, expected $before plus ours; not uploading" >&2
        exit 1
    fi
    good_sigs "$WORK/merged/$name" "$signed" | grep -qxF "$ours" || {
        echo "$name: our signature does not verify in the merged file; not uploading" >&2
        exit 1
    }
    echo "$name: appending our signature to the $before already published"
    gh release upload --clobber "$TAG" "$WORK/merged/$name"
done
