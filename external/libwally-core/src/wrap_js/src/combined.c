#define SECP256K1_BUILD 1
#include "internal.c"
#include "address.c"
#include "aes.c"
#include "anti_exfil.c"
#include "base58.c"
#include "base64.c"
#include "bech32.c"
#include "blech32.c"
#include "bip32.c"
#include "bip38.c"
#include "bip39.c"
#include "ecdh.c"
#include "elements.c"
#include "hex.c"
#include "hmac.c"
#include "mnemonic.c"
#include "pbkdf2.c"
#include "pullpush.c"
#include "psbt.c"
#include "script.c"
#include "scrypt.c"
#include "sign.c"
#include "symmetric.c"
#include "transaction.c"
#include "wif.c"
#include "wordlist.c"
#undef PACKAGE
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_URL
#undef PACKAGE_VERSION
#undef VERSION
#undef SECP256K1_BUILD
#include "src/secp256k1/src/secp256k1.c"
#include "src/secp256k1/src/precomputed_ecmult_gen.c"
#include "src/secp256k1/src/precomputed_ecmult.c"
#include "ccan/ccan/crypto/sha256/sha256.c"

void wally_silence_unused_warnings(void)
{
    assert_sign_assumptions();
    assert_bip32_assumptions();
    assert_bip38_assumptions();
    assert_tx_assumptions();
    secp256k1_fe_get_bounds(NULL, 0);
    secp256k1_fe_inv_var(NULL, NULL);
    secp256k1_ge_set_all_gej_var(NULL, NULL, 0);
    secp256k1_gej_has_quad_y_var(NULL);
    secp256k1_ge_is_valid_var(NULL);
    secp256k1_ge_set_infinity(NULL);
    secp256k1_ec_commit_verify(NULL, NULL, NULL, NULL, 0);
    secp256k1_ecmult_multi_var(NULL, NULL, NULL, NULL, NULL, NULL, 0);
    secp256k1_ecmult_strauss_batch_single(NULL, NULL, NULL, NULL, NULL, NULL, 0);
    secp256k1_ecmult_pippenger_batch_single(NULL, NULL, NULL, NULL, NULL, NULL, 0);
    secp256k1_pippenger_scratch_size(0, 0);
    secp256k1_scalar_chacha20(NULL, NULL, NULL, 0);
    secp256k1_sha256_initialize_tagged(NULL, NULL, 0);
    tx_elements_input_issuance_proof_init(NULL, NULL, 0, NULL, 0);
    tx_elements_output_proof_init(NULL, NULL, 0, NULL, 0);
    witness_stack_from_bytes(NULL, NULL, NULL);
}
