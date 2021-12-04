#!/usr/bin/env python

import os
import pathlib
import subprocess

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as build_ext_orig


cwd = pathlib.Path(os.path.dirname(__file__))


class ClExtension(Extension):
    def __init__(self, name, **kwargs):
        # don't invoke the original build_ext for this special extension
        super().__init__(name, **kwargs)


# The directory we compile external depencies is architecture specific.
external_target = pathlib.Path("external") / subprocess.check_output(
    ["gcc", "-dumpmachine"]
).strip().decode("ASCII")


class build_ext(build_ext_orig):
    def run(self):
        for ext in self.extensions:
            self.build_make(ext)
        super().run()

    def build_make(self, ext):
        cwd = pathlib.Path().absolute()
        srcdir = cwd / "src"

        if not srcdir.exists():
            subprocess.check_call(
                [
                    "git",
                    "clone",
                    "--recursive",
                    '--branch=libhsmd-python',
                    "https://github.com/cdecker/lightning.git",
                    "src",
                ],
                cwd=cwd,
            )

        subprocess.check_call([
            "./configure",
            "--disable-developer",
            "--disable-valgrind",
            "CC=gcc"
        ], cwd=cwd / "src")

        # Selectively build some targets we rely on later
        subprocess.check_call(["make", "lightningd/lightning_hsmd"], cwd=srcdir)


# Absolute include dirs which we will later expand to full paths.
include_dirs = [
    ".",
    "ccan/",
    f"{external_target}/libbacktrace-build/",
    "external/libbacktrace/",
    "external/libsodium/src/libsodium/include/sodium/",
    "external/libwally-core/",
    "external/libwally-core/include/",
    "external/libwally-core/src/",
    "external/libwally-core/src/ccan/",
    "external/libwally-core/src/secp256k1/",
    "external/libwally-core/src/secp256k1/include/",
    "external/libwally-core/src/secp256k1/src",
    'contrib/libhsmd_python/',
]

sources = [
    "bitcoin/block.c",
    "bitcoin/chainparams.c",
    "bitcoin/preimage.c",
    "bitcoin/privkey.c",
    "bitcoin/psbt.c",
    "bitcoin/pubkey.c",
    "bitcoin/script.c",
    "bitcoin/shadouble.c",
    "bitcoin/short_channel_id.c",
    "bitcoin/signature.c",
    "bitcoin/tx.c",
    "bitcoin/varint.c",
    "ccan/ccan/breakpoint/breakpoint.c",
    "ccan/ccan/crypto/hkdf_sha256/hkdf_sha256.c",
    "ccan/ccan/crypto/hmac_sha256/hmac_sha256.c",
    "ccan/ccan/crypto/shachain/shachain.c",
    "ccan/ccan/crypto/siphash24/siphash24.c",
    "ccan/ccan/err/err.c",
    "ccan/ccan/fdpass/fdpass.c",
    "ccan/ccan/htable/htable.c",
    "ccan/ccan/intmap/intmap.c",
    "ccan/ccan/io/fdpass/fdpass.c",
    "ccan/ccan/io/io.c",
    "ccan/ccan/io/poll.c",
    "ccan/ccan/isaac/isaac64.c",
    "ccan/ccan/list/list.c",
    "ccan/ccan/noerr/noerr.c",
    "ccan/ccan/ptr_valid/ptr_valid.c",
    "ccan/ccan/read_write_all/read_write_all.c",
    "ccan/ccan/str/hex/hex.c",
    "ccan/ccan/take/take.c",
    "ccan/ccan/tal/str/str.c",
    "ccan/ccan/tal/tal.c",
    "ccan/ccan/time/time.c",
    "ccan/ccan/timer/timer.c",
    "ccan/ccan/utf8/utf8.c",
    "common/amount.c",
    "common/autodata.c",
    "common/bigsize.c",
    "common/bip32.c",
    "common/bolt12_merkle.c",
    "common/channel_id.c",
    "common/daemon.c",
    "common/daemon_conn.c",
    "common/derive_basepoints.c",
    "common/hash_u5.c",
    "common/hsm_encryption.c",
    "common/key_derive.c",
    "common/memleak.c",
    "common/msg_queue.c",
    "common/node_id.c",
    "common/pseudorand.c",
    "common/setup.c",
    "common/status.c",
    "common/status_levels.c",
    "common/status_wire.c",
    "common/status_wiregen.c",
    "common/subdaemon.c",
    "common/type_to_string.c",
    "common/utils.c",
    "common/utxo.c",
    "common/version.c",
    "contrib/libhsmd_python/shims.c",
    "contrib/libhsmd_python/swig_wrap.c",
    "external/libbacktrace/alloc.c",
    "external/libbacktrace/backtrace.c",
    "external/libbacktrace/fileline.c",
    "external/libbacktrace/posix.c",
    "external/libbacktrace/print.c",
    "external/libbacktrace/simple.c",
    "external/libbacktrace/state.c",
    "external/libbacktrace/unknown.c",
    "external/libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c",
    "external/libsodium/src/libsodium/crypto_core/hchacha20/core_hchacha20.c",
    "external/libsodium/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c",
    "external/libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c",
    "external/libsodium/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c",
    "external/libsodium/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c",
    "external/libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c",
    "external/libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c",
    "external/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-core.c",
    "external/libsodium/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c",
    "external/libsodium/src/libsodium/crypto_pwhash/argon2/blake2b-long.c",
    "external/libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c",
    "external/libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c",
    "external/libsodium/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c",
    "external/libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c",
    "external/libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c",
    "external/libsodium/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c",
    "external/libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20.c",
    "external/libsodium/src/libsodium/crypto_verify/sodium/verify.c",
    "external/libsodium/src/libsodium/randombytes/randombytes.c",
    "external/libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c",
    "external/libsodium/src/libsodium/sodium/core.c",
    "external/libsodium/src/libsodium/sodium/runtime.c",
    "external/libsodium/src/libsodium/sodium/utils.c",
    "external/libwally-core/src/base58.c",
    "external/libwally-core/src/bip32.c",
    "external/libwally-core/src/ccan/ccan/base64/base64.c",
    "external/libwally-core/src/ccan/ccan/crypto/ripemd160/ripemd160.c",
    "external/libwally-core/src/ccan/ccan/crypto/sha256/sha256.c",
    "external/libwally-core/src/ccan/ccan/crypto/sha512/sha512.c",
    "external/libwally-core/src/hex.c",
    "external/libwally-core/src/hmac.c",
    "external/libwally-core/src/internal.c",
    "external/libwally-core/src/psbt.c",
    "external/libwally-core/src/pullpush.c",
    "external/libwally-core/src/script.c",
    "external/libwally-core/src/secp256k1/src/secp256k1.c",
    "external/libwally-core/src/sign.c",
    "external/libwally-core/src/transaction.c",
    "hsmd/hsmd_wiregen.c",
    "hsmd/libhsmd.c",
    "hsmd/libhsmd_status.c",
    "contrib/libhsmd_python/libhsmd_python.c",
    "wire/fromwire.c",
    "wire/peer_wire.c",
    "wire/peer_wiregen.c",
    "wire/tlvstream.c",
    "wire/towire.c",
    "wire/wire_io.c",
    "wire/wire_sync.c",
]

include_dirs = [os.path.join("src", f) for f in include_dirs]
sources = [os.path.join("src", f) for f in sources]

configtuples = []
if pathlib.Path('src/config.vars').exists():
    configvars = open("src/config.vars", "r").readlines()
    configtuples = [tuple(v.strip().split("=", 1)) for v in configvars]

libhsmd_module = ClExtension(
    "_libhsmd",
    libraries=["sodium"],
    include_dirs=include_dirs,
    define_macros=configtuples
    + [
        ("BUILD_ELEMENTS", "1"),
        ("SHACHAIN_BITS", "48"),
        ("USE_NUM_NONE", "1"),
        ("ECMULT_WINDOW_SIZE", "15"),
        ("ECMULT_GEN_PREC_BITS", "4"),
        ("USE_SCALAR_INV_BUILTIN", "1"),
        ("USE_FIELD_INV_BUILTIN", "1"),
        ("ENABLE_MODULE_EXTRAKEYS", "1"),
        ("ENABLE_MODULE_RECOVERY", "1"),
        ("ENABLE_MODULE_SCHNORRSIG", "1"),
        ("ENABLE_MODULE_ECDH", "1"),
    ],
    sources=sources,
)

setup(
    name="libhsmd",
    version="0.10.0",
    author="Christian Decker",
    author_email="cdecker@blockstream.com",
    description="""Python wrapper to the libhsmd library""",
    url="https://github.com/ElementsProject/lightning/tree/master/contrib/libhsmd_python/",
    ext_modules=[libhsmd_module],
    py_modules=["libhsmd"],
    cmdclass={
        "build_ext": build_ext,
    },
    long_description=open(cwd / "README.md", "r").read(),
    long_description_content_type="text/markdown",
    license="BSD-MIT"
)
