## Tests in list

test_pay.py::test_sendpay

#### proxy and server done

1   hsm_ecdh_req						ECDH
7   hsm_sign_withdrawal					SignWithdrawalTx
9   hsm_client_hsmfd					PassClientHSMFd
11  hsm_init							InitHSM
19  hsm_sign_remote_commitment_tx		SignRemoteCommitmentTx

#### proxy done, but server not complete

3   hsm_cupdate_sig_req					ChannelUpdateSig
8   hsm_sign_invoice					SignInvoice
18  hsm_get_per_commitment_point		GetPerCommitmentPoint
20  hsm_sign_remote_htlc_tx				SignRemoteHTLCTx

#### need proxy and server

10  hsm_get_channel_basepoints

