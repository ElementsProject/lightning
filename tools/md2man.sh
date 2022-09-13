#! /bin/sh

if [ $# != 2 ]; then
    echo "Usage: $0 <lowdown> <markdownpage>" >&2
    exit 1
fi
LOWDOWN="$1"
SOURCE="$2"
SECTION="$(basename "$SOURCE" .md | cut -d. -f2-)"
TITLE="$(basename "$(basename "$SOURCE" .md)" ."$SECTION" | tr '[:lower:]' '[:upper:]')"

# First two lines are title, which needs to be turned into NAME for proper manpage
# format.  mrkd used to do this for us, lowdown(1) doesn't.
TITLELINE="$(head -n1 "$SOURCE")"

(echo "NAME"; echo "----"; echo "$TITLELINE"; tail -n +3 "$SOURCE") | $LOWDOWN -s --out-no-smarty -Tman -m "title:$TITLE" -m "section:$SECTION" -m "source:Core Lightning $VERSION" -m "shiftheadinglevelby:-1"
