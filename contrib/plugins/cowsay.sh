#! /bin/sh

# Set sed using best effort, for MacOS.
if which gsed > /dev/null; then SED="gsed"; else SED="sed"; fi

maybe_cowsay()
{
    cowsay || cat <<EOF
 _________________________________
< Please install 'cowsay' program >
 ---------------------------------
        \\   ^__^
         \\  (xx)\\_______
            (__)\\       )\\/\\
             U  ||----w |
                ||     ||
EOF
}

# Eg. {"jsonrpc":"2.0","id":2,"method":"getmanifest","params":{}}\n\n
read -r JSON
read -r _
id=$(echo "$JSON" | $SED 's/.*"id" *: *\([^,]*\),.*/\1/')

echo '{"jsonrpc":"2.0","id":'"$id"',"result":{"dynamic":true,"options":[],"rpcmethods":[{"name":"cowsay","usage":"<string>","description":"Have a cow, man!"}]}}'

# Eg. {"jsonrpc":"2.0","id":5,"method":"init","params":{"options":{},"configuration":{"lightning-dir":"/home/rusty/.lightning","rpc-file":"lightning-rpc","startup":false}}}\n\n
read -r JSON
read -r _
id=$(echo "$JSON" | $SED 's/.*"id" *: *\([^,]*\),.*/\1/')

echo '{"jsonrpc":"2.0","id":'"$id"',"result":{}}'

# eg. { "jsonrpc" : "2.0", "method" : "cowsay", "id" : 6, "params" :[ "hello"] }
while read -r JSON; do
    read -r _
    id=$(echo "$JSON" | $SED 's/.*"id" *: *\([^,]*\),.*/\1/')
    params=$(echo "$JSON" | $SED 's/.*"params" *: *//' | tr -d '[{}]"')
    echo '{"jsonrpc":"2.0","id":'"$id"',"result":{"format-hint":"simple","cowsay":"'
    # FIXME: lightning-cli does not unescape \\, so we replace with an L.
    printf "%s" "$params" | maybe_cowsay | $SED 's/\\/L/g' | $SED ':a;N;$!ba;s/\n/\\n/g' | tr '\012' '"'
    echo '}}'
done
