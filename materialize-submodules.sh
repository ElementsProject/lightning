git rm .gitmodules
git rm --cached external/jsmn external/libbase58 external/libsodium external/libbacktrace external/libwally-core
rm -rf external/jsmn external/libbase58 external/libsodium external/libbacktrace external/libwally-core

rm -rf .git/modules/external/jsmn .git/modules/external/libbase58 .git/modules/external/libsodium .git/modules/external/libbacktrace .git/modules/external/libwally-core

git commit -am "scripted: Remove submodules for materialization"

git clone --recursive https://github.com/zserge/jsmn external/jsmn
(cd external/jsmn; git checkout 6784c826d9674915a4d89649c6288e6aecb4110d)

git clone --recursive https://github.com/bitcoin/libbase58.git external/libbase58
(cd external/libbase58; git checkout 16c2527608053d2cc2fa05b2e3b5ae96065d1410)

git clone --recursive https://github.com/jedisct1/libsodium.git external/libsodium
(cd external/libsodium; git checkout 675149b9b8b66ff44152553fb3ebf9858128363d)

git clone --recursive https://github.com/ianlancetaylor/libbacktrace.git external/libbacktrace
(cd external/libbacktrace; git checkout 5a99ff7fed66b8ea8f09c9805c138524a7035ece)

git clone --recursive https://github.com/ElementsProject/libwally-core.git external/libwally-core
(cd external/libwally-core; git checkout c51bca3379545e1aaaa78a25cc2b73e589a6ad79)

rm -rf external/jsmn/.git external/libbase58/.git/ external/libsodium/.git/ external/libbacktrace/.git/ external/libwally-core/.git

# Move gitignore out of the way so the following adds work
mv .gitignore .gitignore.bak

git add external/jsmn
git add external/libbase58
git add external/libsodium
git add external/libbacktrace
git add external/libwally-core

mv .gitignore.bak .gitignore

git commit -am "scripted: Materialize submodules"
