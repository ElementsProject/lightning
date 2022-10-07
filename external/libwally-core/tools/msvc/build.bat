set LIBWALLY_DIR=%cd%

REM Need to first build gen_context.exe to generate a header file
REM It seems possible to skip this step and remove the definition
REM of USE_ECMULT_STATIC_PRECOMPUTATION  from the compiler flags
call "%~dp0\gen_ecmult_static_context.bat"

REM There are duplicate file names in both the wally and ccan sources
REM In a sane build system this would not be a problem but because
REM everything is being munged together for Windows as a hack it causes
REM problems. Make renamed copies as a workaround.
copy src\ccan\ccan\str\hex\hex.c src\ccan\ccan\str\hex\hex_.c
copy src\ccan\ccan\base64\base64.c src\ccan\ccan\base64\base64_.c

if "%ELEMENTS_BUILD%" == "elements" (
  set ELEMENTS_OPT=/DBUILD_ELEMENTS
) else (
  set ELEMENTS_OPT=
)

REM Compile everything (wally, ccan, libsecp256k) in one lump.
REM Define USE_ECMULT_STATIC_PRECOMPUTATION  to pick up the
REM ecmult_static_context.h file generated previously
cl /utf-8 /DUSE_ECMULT_STATIC_PRECOMPUTATION /DECMULT_WINDOW_SIZE=15 /DWALLY_CORE_BUILD %ELEMENTS_OPT% /DHAVE_CONFIG_H /DSECP256K1_BUILD /I%LIBWALLY_DIR%\src\wrap_js\windows_config /I%LIBWALLY_DIR% /I%LIBWALLY_DIR%\src /I%LIBWALLY_DIR%\include /I%LIBWALLY_DIR%\src\ccan /I%LIBWALLY_DIR%\src\ccan\base64 /I%LIBWALLY_DIR%\src\secp256k1 /Zi /LD src/aes.c src/anti_exfil.c src/base58.c src/base64.c src/bech32.c src/bip32.c src/bip38.c src/bip39.c src/blech32.c src/ecdh.c src/elements.c src/hex.c src/hmac.c src/internal.c src/mnemonic.c src/pbkdf2.c src/psbt.c src/script.c src/scrypt.c src/sign.c src/symmetric.c src/transaction.c src/wif.c src/wordlist.c src/ccan/ccan/crypto/ripemd160/ripemd160.c src/ccan/ccan/crypto/sha256/sha256.c src/ccan/ccan/crypto/sha512/sha512.c src/ccan/ccan/base64/base64_.c src\ccan\ccan\str\hex\hex_.c src/secp256k1/src/secp256k1.c src/secp256k1/src/precomputed_ecmult_gen.c src/secp256k1/src/precomputed_ecmult.c /Fewally.dll
