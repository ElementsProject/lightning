#!/bin/bash
set -e

: "${TIMEOUT:=${1:-60}}"
let DEADLINE=EPOCHSECONDS+TIMEOUT

lightning-cli() {
	echo lightning-cli "${@@Q}" >&2
	command lightning-cli "${@}" >&2
}

lightning-cli setconfig snub-idle-channels true true
while (( EPOCHSECONDS < DEADLINE )) ; do
	echo "Attempting graceful stop ($((DEADLINE - EPOCHSECONDS))s remaining) ..."
	while read -r rpc ; do
		if [[ "${rpc}" == '# '* ]] ; then
			set ${rpc}
			echo "# ${2} reestablished channels, ${3} outstanding HTLCs" >&2
			next_expiry=${4}
		else
			eval "lightning-cli ${rpc}"
			if [[ "${rpc}" == stop ]] ; then
				echo 'Graceful stop succeeded.'
				exit 0
			fi
		fi
	done < <(command lightning-cli listpeerchannels | jq -r '
		reduce (.channels[] | select(.state | IN("CHANNELD_NORMAL", "CHANNELD_AWAITING_SPLICE")))
			as { $peer_id, $peer_connected, $reestablished, $state, $htlcs }
		(
			{};
			.[$peer_id] |= (
				.connected |= . or $peer_connected |
				.reestablished += if $reestablished then 1 else 0 end |
				.htlcs += ($htlcs | length) |
				.next_expiry |= ([. // empty, $htlcs[].expiry] | min)
			)
		) |
		(
			"# \(map(.reestablished) | add) \(map(.htlcs) | add) \(map(.next_expiry // empty) | min)",
			if all(.reestablished == 0) and all(.htlcs == 0) then
				"stop"
			else
				to_entries[] |
				select(.value | .connected and .reestablished > 0 and .htlcs == 0) |
				@sh "disconnect \(.key) true"
			end
		)
	')
	sleep 1
done
let headercount=$(command lightning-cli getchaininfo | jq '.headercount')
fmt --width="${COLUMNS:-80}" <<EOF

Graceful stop timed out after ${TIMEOUT} seconds.
An outstanding HTLC will next expire at block height ${next_expiry} in about $((next_expiry - headercount))0 minutes.
The node is still trying to stop gracefully.
To cancel, run \`lightning-cli setconfig snub-idle-channels false true\`.
EOF
exit 1
