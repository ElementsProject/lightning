Notes on the musig module API
===========================

The following sections contain additional notes on the API of the musig module (`include/secp256k1_musig.h`).
A usage example can be found in `examples/musig.c`.

# API misuse

The musig API is designed to be as misuse resistant as possible.
However, the MuSig protocol has some additional failure modes (mainly due to interactivity) that do not appear in single-signing.
While the results can be catastrophic (e.g. leaking of the secret key), it is unfortunately not possible for the musig implementation to rule out all such failure modes.

Therefore, users of the musig module must take great care to make sure of the following:

1. A unique nonce per signing session is generated in `secp256k1_musig_nonce_gen`.
   See the corresponding comment in `include/secp256k1_musig.h` for how to ensure that.
2. The `secp256k1_musig_secnonce` structure is never copied or serialized.
   See also the comment on `secp256k1_musig_secnonce` in `include/secp256k1_musig.h`.
3. Opaque data structures are never written to or read from directly.
   Instead, only the provided accessor functions are used.
4. If adaptor signatures are used, all partial signatures are verified.

# Key Aggregation and (Taproot) Tweaking

Given a set of public keys, the aggregate public key is computed with `secp256k1_musig_pubkey_agg`.
A (Taproot) tweak can be added to the resulting public key with `secp256k1_xonly_pubkey_tweak_add`.

# Signing

This is covered by `examples/musig.c`.
Essentially, the protocol proceeds in the following steps:

1. Generate a keypair with `secp256k1_keypair_create` and obtain the xonly public key with `secp256k1_keypair_xonly_pub`.
2. Call `secp256k1_musig_pubkey_agg` with the xonly pubkeys of all participants.
3. Optionally add a (Taproot) tweak with `secp256k1_musig_pubkey_tweak_add`.
4. Generate a pair of secret and public nonce with `secp256k1_musig_nonce_gen` and send the public nonce to the other signers.
5. Someone (not necessarily the signer) aggregates the public nonce with `secp256k1_musig_nonce_agg` and sends it to the signers.
6. Process the aggregate nonce with `secp256k1_musig_nonce_process`.
7. Create a partial signature with `secp256k1_musig_partial_sign`.
8. Verify the partial signatures (optional in some scenarios) with `secp256k1_musig_partial_sig_verify`.
9. Someone (not necessarily the signer) obtains all partial signatures and aggregates them into the final Schnorr signature using `secp256k1_musig_partial_sig_agg`.

The aggregate signature can be verified with `secp256k1_schnorrsig_verify`.

Note that steps 1 to 6 can happen before the message to be signed is known to the signers.
Therefore, the communication round to exchange nonces can be viewed as a pre-processing step that is run whenever convenient to the signers.
This disables some of the defense-in-depth measures that may protect against API misuse in some cases.
Similarly, the API supports an alternative protocol flow where generating the aggregate key (steps 1 to 3) is allowed to happen after exchanging nonces (steps 4 to 6).

# Verification

A participant who wants to verify the partial signatures, but does not sign itself may do so using the above instructions except that the verifier skips steps 1, 4 and 7.

# Atomic Swaps

The signing API supports the production of "adaptor signatures", modified partial signatures
which are offset by an auxiliary secret known to one party. That is,
1. One party generates a (secret) adaptor `t` with corresponding (public) adaptor `T = t*G`.
2. When calling `secp256k1_musig_nonce_process`, the public adaptor `T` is provided as the `adaptor` argument.
3. The party who is going to extract the secret adaptor `t` later must verify all partial signatures.
4. Due to step 2, the signature output of `secp256k1_musig_partial_sig_agg` is a pre-signature and not a valid Schnorr signature. All parties involved extract this session's `nonce_parity` with `secp256k1_musig_nonce_parity`.
5. The party who knows `t` must "adapt" the pre-signature with `t` (and the `nonce_parity` using `secp256k1_musig_adapt` to complete the signature.
6. Any party who sees both the final signature and the pre-signature (and has the `nonce_parity`) can extract `t` with `secp256k1_musig_extract_adaptor`.
