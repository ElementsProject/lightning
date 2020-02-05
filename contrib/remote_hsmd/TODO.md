
API Coverage
----------------------------------------------------------------

## Failing Tests

tests/test_connection.py::test_restart_many_payments
tests/test_misc.py::test_signmessage


#### proxy and server done

1   hsm_ecdh_req						ECDH
7   hsm_sign_withdrawal					SignWithdrawalTx
9   hsm_client_hsmfd					PassClientHSMFd
11  hsm_init							InitHSM
19  hsm_sign_remote_commitment_tx		SignRemoteCommitmentTx

#### proxy done, but server not complete

3   hsm_cupdate_sig_req					ChannelUpdateSig
8   hsm_sign_invoice					SignInvoice
10  hsm_get_channel_basepoints			GetChannelBasepoints
18  hsm_get_per_commitment_point		GetPerCommitmentPoint
20  hsm_sign_remote_htlc_tx				SignRemoteHTLCTx
    HSM_SIGN_MUTUAL_CLOSE_TX			SignMutualCloseTx
    HSM_SIGN_COMMITMENT_TX				SignCommitmentTx
    WIRE_HSM_CANNOUNCEMENT_SIG_REQ
    WIRE_HSM_NODE_ANNOUNCEMENT_SIG_REQ
    WIRE_HSM_SIGN_PENALTY_TO_US
    WIRE_HSM_SIGN_DELAYED_PAYMENT_TO_US
    WIRE_HSM_SIGN_LOCAL_HTLC_TX
    WIRE_HSM_SIGN_REMOTE_HTLC_TO_US
    handle_check_future_secret

#### need proxy and server

handle_sign_funding_tx
handle_sign_message

Improvements
----------------------------------------------------------------

#### Remove contrib/remote_signer/hsm_wire.csv

Generate gen_hsm_wire.{h,c} from c-lightning/hsmd/hsm_wire.csv instead.
  
