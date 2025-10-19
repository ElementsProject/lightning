#! /bin/sh

if [ $# != 2 ]; then
    echo "Usage: $0 <lowdown> <markdownpage>" >&2
    exit 1
fi
LOWDOWN="$1"
SOURCE="$2"

TARGET="$SOURCE"

# Extract the directory and filename separately
DIR="$(dirname "$SOURCE")"
FILE="$(basename "$SOURCE" .md)"

# Check if the file doesn't already start with 'lightningd' or 'lightning-'
if [ "${FILE#lightningd}" = "$FILE" ] && [ "${FILE#lightning-}" = "$FILE" ]; then
    TARGET="$DIR/lightning-$FILE"
fi
TARGET="${TARGET%.md}"

SECTION="$(basename "$SOURCE" .md | cut -d. -f2-)"
TITLE="$(basename "$(basename "$TARGET" .md)" ."$SECTION" | tr '[:lower:]' '[:upper:]')"

# First two lines are title, which needs to be turned into NAME for proper manpage
# format.  mrkd used to do this for us, lowdown(1) doesn't.
TITLELINE="$(head -n1 "$SOURCE")"

# Replace lightning-cli with $ lightning-cli but do not replace it if it is preceded with (
# because it is used in the examples to run it in the shell, eg. $(lightning-cli listpeerchannels)
# shellcheck disable=SC2016 # These are not variables, shellcheck!
SOURCE=$(tail -n +3 "$SOURCE" | $SED -E '
    :a;N;$!ba;
    s#(\(lightning-cli)#\x1#ig;
    s#lightning-cli#$ lightning-cli#g;
    s#\x1#(lightning-cli#g;
' |
# Lowdown requires a blank line before every preformatted text block
$SED '
	/^$/{:0;N;/\n$/b0};s/^[[:blank:]]*```/\n\0/;
	/\n[[:blank:]]*```/{:1;n;/^[[:blank:]]*```/!b1}
')

# Output to the target file
(echo "NAME"; echo "----"; echo "$TITLELINE"; echo "$SOURCE") | $LOWDOWN -s --out-no-smarty -Tman -m "title:$TITLE" -m "section:$SECTION" -m "source:Core Lightning $VERSION" -m "shiftheadinglevelby:-1" > "$TARGET"
