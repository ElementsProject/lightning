from templates import js, nan, java, swift
import export_js_constants
import sys, os

class FuncSpec(object):

    def __init__(self, arguments, out_size=None, wally_name=None, nodejs_append_alloc=False, out_sizes=None):
        self.arguments = arguments
        self.out_size = out_size
        self.wally_name = wally_name
        self.nodejs_append_alloc = nodejs_append_alloc
        self.out_sizes = out_sizes


F = FuncSpec

SHA256_LEN = 32
SHA512_LEN = 64
HASH160_LEN = 20
HMAC_SHA256_LEN = 32
HMAC_SHA512_LEN = 64
PBKDF2_HMAC_SHA256_LEN = 32
PBKDF2_HMAC_SHA512_LEN = 64
WALLY_WITNESSSCRIPT_MAX_LEN = 42
BITCOIN_MESSAGE_FLAG_HASH = 1


hash_func_spec = lambda out_size: F(
    ['const_bytes', ('out_bytes', out_size)]
)


hmac_func_spec = lambda out_size: F(
    ['const_bytes[key]', 'const_bytes[bytes]', ('out_bytes', out_size)]
)


pbkdf_func_spec = lambda out_size: F(
    ['const_bytes[pass]', 'const_bytes[salt]',
     'uint32_t[flags]', 'uint32_t[cost]',
     ('out_bytes', out_size)]
)


FUNCS = [
    # hashes + PBKDF2:
    ('wally_sha256', hash_func_spec(SHA256_LEN)),
    ('wally_sha256d', hash_func_spec(SHA256_LEN)),
    ('wally_sha512', hash_func_spec(SHA512_LEN)),
    ('wally_hash160', hash_func_spec(HASH160_LEN)),
    ('wally_hmac_sha256', hmac_func_spec(HMAC_SHA256_LEN)),
    ('wally_hmac_sha512', hmac_func_spec(HMAC_SHA512_LEN)),
    ('wally_pbkdf2_hmac_sha256', pbkdf_func_spec(PBKDF2_HMAC_SHA256_LEN)),
    ('wally_pbkdf2_hmac_sha512', pbkdf_func_spec(PBKDF2_HMAC_SHA512_LEN)),

    # base58:
    ('wally_base58_from_bytes', F([
        'const_bytes[bytes]', 'uint32_t[flags]', 'out_str_p'
    ])),
    ('wally_base58_to_bytes', F([
        'string[b58]', 'uint32_t[flags]', 'out_bytes_sized'
    ], out_size='_arguments[0].length + ((_arguments[1] & 1) ? 4 : 0)')),

    # address
    ('wally_addr_segwit_from_bytes', F([
        'const_bytes[bytes]', 'string[addr_family]', 'uint32_t[flags]', 'out_str_p'
    ])),

    ('wally_addr_segwit_to_bytes', F([
        'string[addr]', 'string[addr_family]', 'uint32_t[flags]', 'out_bytes_sized'
    ], out_size=str(WALLY_WITNESSSCRIPT_MAX_LEN))),

    ('wally_wif_to_bytes', F([
        'const_char[wif]', 'uint32_t[prefix]', 'uint32_t[flags]', 'out_bytes_fixedsized'
    ], out_size='32')),
    ('wally_wif_is_uncompressed', F([
        'const_char[wif]', 'out_bool_by_size_t'
    ])),

    # AES:
    ('wally_aes', F([
        'const_bytes[key]', 'const_bytes[bytes]', 'uint32_t[flags]',
        'out_bytes_fixedsized'
    ], out_size='_arguments[1].length')),
    ('wally_aes_cbc', F([
        'const_bytes[key]', 'const_bytes[iv]', 'const_bytes[bytes]',
        'uint32_t[flags]', 'out_bytes_sized'
    ], out_size='Math.ceil(_arguments[2].length / 16) * 16 + 16')),

    # Script:
    ('wally_scriptpubkey_multisig_from_bytes', F([
        'const_bytes[bytes]', 'uint32_t[threshold]', 'uint32_t[flags]',
        'out_bytes_sized'
    ], out_size='Math.ceil(_arguments[0].length / 33) * 34 + 3')),

    # Scrypt:
    ('wally_scrypt', F([
        'const_bytes[passwd]', 'const_bytes[salt]',
        'uint32_t[cost]', 'uint32_t[block]', 'uint32_t[parallel]',
        'out_bytes_fixedsized'
    ])),  # out_size is passed from js directly

    # BIP38:
    ('bip38_raw_from_private_key', F([
        'const_bytes[key]', 'const_bytes[pass]', 'uint32_t[flags]',
        'out_bytes_fixedsized'
    ], out_size='39')),
    ('bip38_from_private_key', F([
        'const_bytes[key]', 'const_bytes[pass]', 'uint32_t[flags]',
        'out_str_p'
    ])),
    ('bip38_raw_to_private_key', F([
        'const_bytes[bip38]', 'const_bytes[pass]', 'uint32_t[flags]',
        'out_bytes_fixedsized'
    ], out_size='32')),
    ('bip38_to_private_key', F([
        'string[bip38]', 'const_bytes[pass]', 'uint32_t[flags]',
        'out_bytes_fixedsized'
    ], out_size='32')),

    # BIP39:
    ('bip39_get_languages', F([
        'out_str_p'])),
    ('bip39_mnemonic_from_bytes', F([
        'bip39_words_lang_in', 'const_bytes[entropy]',
        'out_str_p'])),
    ('bip39_mnemonic_to_seed', F([
        'string[mnemonic]', 'string[pass]', 'out_bytes_sized'
    ], out_size='64')),

    # signing:
    ('wally_ec_sig_from_bytes', F([
        'const_bytes[key]', 'const_bytes[bytes]', 'uint32_t[flags]',
        'out_bytes_fixedsized'
    ], out_size='64 + ((_arguments[2] & 8) ? 1 : 0)')),

    # signatures:
    ('wally_ec_sig_to_der', F([
        'const_bytes[sig]', 'out_bytes_sized'
    ], out_size='72')),
    ('wally_ec_sig_to_public_key', F([
        'const_bytes[bytes]', 'const_bytes[sig]', 'out_bytes_fixedsized'
    ], out_size='33')),

    # BIP32:
    ('bip32_key_from_seed', F([
        'const_bytes[seed]', 'uint32_t[version]', 'uint32_t[flags]',
        'bip32_priv_out'
    ], wally_name='bip32_key_from_seed', nodejs_append_alloc=True)),
    ('bip32_privkey_from_parent', F([
        'bip32_in', 'uint32_t[child_num]', 'uint32_t[flags]', 'bip32_priv_out'
    ], wally_name='bip32_key_from_parent', nodejs_append_alloc=True)),
    ('bip32_pubkey_from_parent', F([
        'bip32_in', 'uint32_t[child_num]', 'uint32_t[flags]', 'bip32_pub_out'
    ], wally_name='bip32_key_from_parent', nodejs_append_alloc=True)),
    ('bip32_key_get_priv_key', F([
        'bip32_in', 'out_bytes_fixedsized'
    ], out_size='32')),
    ('bip32_key_get_pub_key', F([
        'bip32_in', 'out_bytes_fixedsized'
    ], out_size='33')),

    ('wally_ec_public_key_from_private_key', F([
        'const_bytes[key]', 'out_bytes_fixedsized'
    ], out_size='33')),
    ('wally_ec_private_key_verify', F([
        'const_bytes[key]', 'out_is_success'
    ])),
    ('wally_ec_public_key_verify', F([
        'const_bytes[key]', 'out_is_success'
    ])),
    ('wally_tx_from_hex', F([
        'const_char', 'uint32_t[flags]', 'tx_out'
    ])),
    ('wally_format_bitcoin_message', F([
        'const_bytes[message]', 'uint32_t[flags]',
    'out_bytes_sized'
    ], out_size='_arguments[1] & {} ? {} : 2 + "Bitcoin Signed Message:".length + _arguments[0].length + (_arguments[0].length < 253 ? 1 : 3)'.format(
        BITCOIN_MESSAGE_FLAG_HASH, SHA256_LEN))),
]
FUNCS_NODE = [
    # Assets:
    ('wally_asset_generator_from_bytes', F([
        'const_bytes[asset]', 'const_bytes[abf]', 'out_bytes_fixedsized'
    ], out_size='33')),
    ('wally_asset_final_vbf', F([
        'const_uint64s[values]', 'uint32_t[num_inputs]',
        'const_bytes[abf]', 'const_bytes[vbf]', 'out_bytes_fixedsized'
    ], out_size='32')),
    ('wally_asset_unblind_with_nonce', F([
        'const_bytes[nonce_hash]',
        'const_bytes[rangeproof]',
        'const_bytes[commitment]',
        'const_bytes[extra_in]',
        'const_bytes[generator]',
        'out_bytes_fixedsized',
        'out_bytes_fixedsized',
        'out_bytes_fixedsized',
        'out_uint64_t'
    ], out_sizes=['32', '32', '32'])),
    ('wally_asset_unblind', F([
        'const_bytes[pubkey]',
        'const_bytes[privkey]',
        'const_bytes[rangeproof]',
        'const_bytes[commitment]',
        'const_bytes[extra_in]',
        'const_bytes[generator]',
        'out_bytes_fixedsized',
        'out_bytes_fixedsized',
        'out_bytes_fixedsized',
        'out_uint64_t'
    ], out_sizes=['32', '32', '32'])),
    ('wally_asset_value_commitment', F([
        'uint64_t[value]', 'const_bytes[vbf]', 'const_bytes[generator]',
        'out_bytes_fixedsized'
    ], out_size='33')),
    ('wally_asset_rangeproof_with_nonce', F([
        'uint64_t[value]',
        'const_bytes[nonce_hash]',
        'const_bytes[asset]',
        'const_bytes[abf]',
        'const_bytes[vbf]',
        'const_bytes[commitment]',
        'const_bytes[extra_in]',
        'const_bytes[generator]',
        'uint64_t[min_value]',
        'int[exp]',
        'int[min_bits]',
        'out_bytes_sized',
    ], out_size='5134')),
    ('wally_asset_rangeproof', F([
        'uint64_t[value]',
        'const_bytes[pub_key]',
        'const_bytes[priv_key]',
        'const_bytes[asset]',
        'const_bytes[abf]',
        'const_bytes[vbf]',
        'const_bytes[commitment]',
        'const_bytes[extra_in]',
        'const_bytes[generator]',
        'uint64_t[min_value]',
        'int[exp]',
        'int[min_bits]',
        'out_bytes_sized',
    ], out_size='5134')),
    ('wally_asset_surjectionproof', F([
        'const_bytes[asset_id]', 'const_bytes[abf]',
        'const_bytes[generator]', 'const_bytes[entropy]',
        'const_bytes[input_assets]',
        'const_bytes[input_abfs]', 'const_bytes[input_ags]',
        'out_bytes_sized',
    ], out_size='(2 + Math.floor((_arguments[5].length/32 + 7)/8) + 32 * (1 + (_arguments[5].length/32 > 3 ? 3 : _arguments[5].length/32)))')),
    ('wally_asset_blinding_key_from_seed', F([
        'const_bytes[bytes]',
        'out_bytes_fixedsized',
    ], out_size='64')),
    ('wally_asset_blinding_key_to_ec_private_key', F([
        'const_bytes[bytes]',
        'const_bytes[script]',
        'out_bytes_fixedsized',
    ], out_size='32')),
    ('wally_confidential_addr_from_addr', F([
        'string[address]',
        'uint32_t[prefix]',
        'const_bytes[pub_key]',
        'out_str_p'
     ])),
    ('wally_confidential_addr_to_addr', F([
        'string[address]',
        'uint32_t[prefix]',
        'out_str_p'
     ])),
    ('wally_confidential_addr_to_ec_public_key', F([
        'string[address]', 'uint32_t[prefix]', 'out_bytes_fixedsized'
    ], out_size='33')),
]

def open_file(prefix, name):
    return open(os.path.join(prefix, name), "w")

def main():
    prefix = 'wrap_js/'
    build_type = sys.argv[2]
    try:
        extra_args = sys.argv[3]
    except IndexError:
        extra_args = ''

    node_funcs = FUNCS
    if 'elements' in extra_args:
        node_funcs += FUNCS_NODE

    if sys.argv[1] == 'nodejs':
        # Node.js wrapper using Native Abstractions for Node.js
        with open_file(prefix, 'nodejs_wrap.cc') as f:
            f.write(nan.generate(node_funcs, build_type))
    elif sys.argv[1] == 'wally':
        # JS wrapper to choose cordova or node at run time
        with open_file(prefix, 'wally.js') as f:
            f.write(js.generate(node_funcs, build_type))
            f.write(export_js_constants.generate(os.path.pardir))
    elif sys.argv[1] == 'cordova-java':
        # Java cordova plugin for Android
        with open_file(prefix + 'cordovaplugin', 'WallyCordova.java') as f:
            f.write(java.generate(FUNCS, build_type))
    elif sys.argv[1] == 'cordova-swift':
        # Swift cordova plugin for iOS
        with open_file(prefix + 'cordovaplugin', 'WallyCordova.swift') as f:
            f.write(swift.generate(FUNCS, build_type))


if __name__ == '__main__':
    main()
