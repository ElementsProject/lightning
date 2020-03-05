
API Coverage
----------------------------------------------------------------

## Failing Tests

# Frequently Intermittent
tests/test_connection.py::test_funding_cancel_race
tests/test_misc.py::test_bad_onion_immediate_peer

## Proxy Scoreboard

```
COMPLETE		proxy_stat proxy_handle_ecdh
COMPLETE		proxy_stat proxy_handle_pass_client_hsmfd
COMPLETE		proxy_stat proxy_handle_sign_remote_commitment_tx
COMPLETE		proxy_stat proxy_handle_channel_update_sig
COMPLETE		proxy_stat proxy_handle_sign_node_announcement
COMPLETE		proxy_stat proxy_handle_sign_remote_htlc_tx
COMPLETE		proxy_stat proxy_handle_sign_invoice
COMPLETE		proxy_stat proxy_handle_get_channel_basepoints
COMPLETE		proxy_stat proxy_handle_get_per_commitment_point
COMPLETE		proxy_stat proxy_handle_sign_local_htlc_tx
COMPLETE		proxy_stat proxy_handle_sign_remote_htlc_to_us
COMPLETE		proxy_stat proxy_handle_sign_delayed_payment_to_us
COMPLETE		proxy_stat proxy_handle_sign_penalty_to_us
COMPLETE		proxy_stat proxy_handle_sign_commitment_tx
COMPLETE		proxy_stat proxy_handle_sign_mutual_close_tx
COMPLETE		proxy_stat proxy_handle_check_future_secret
COMPLETE		proxy_stat proxy_handle_sign_message

PARTIAL (-P2SH)	proxy_stat proxy_handle_sign_withdrawal_tx

MARSHALED		proxy_stat proxy_init_hsm
MARSHALED		proxy_stat proxy_handle_cannouncement_sig
```

Improvements
----------------------------------------------------------------

#### Remove contrib/remote_signer/hsm_wire.csv

Generate gen_hsm_wire.{h,c} from c-lightning/hsmd/hsm_wire.csv instead.
  
