#! /bin/sh

if [ $# != 1 ]; then
    echo "Usage: $0 <markdownpage>" >&2
    exit 1
fi
SOURCE=$1
SECTION="$(basename "$SOURCE" .md | cut -d. -f2-)"
TITLE="$(basename "$(basename "$SOURCE" .md)" ."$SECTION" | tr '[:lower:]' '[:upper:]')"

# First two lines are title, which needs to be turned into NAME for proper manpage
# format.  mrkd used to do this for us, lowdown(1) doesn't.
TITLELINE="$(head -n1 "$SOURCE")"

(echo "NAME"; echo "----"; echo "$TITLELINE"; tail -n +3 "$SOURCE") | lowdown -s --out-no-smarty -Tman -m "title:$TITLE" -m "section:$SECTION" -m "source:Core Lightning $VERSION" -m "shiftheadinglevelby:-1"
