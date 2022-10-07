var wally = require('../wally');
var test = require('tape');
var path = require('path');
var fs = require('fs');

var root = path.resolve(__dirname);
var filepath = path.join(root, '../../', 'data/wordlists/vectors.json');
var cases = JSON.parse(fs.readFileSync(path.resolve(filepath), 'utf8'))['english'];

var passphrase = 'TREZOR';

test('BIP39', function(t) {
    t.plan(49);

    wally.bip39_get_languages().then((res) => {
        t.equal(res, 'en es fr it jp zhs zht');
    });

    cases.forEach((item) => {
        wally.bip39_mnemonic_from_bytes('en', Buffer.from(item[0], 'hex')).then((res) => {
            t.equal(res, item[1]);
        });

        wally.bip39_mnemonic_to_seed(Buffer.from(item[1], 'utf-8'), Buffer.from(passphrase, 'utf-8')).then((res) => {
            t.equal(Buffer.from(res).toString('hex'), item[2]);
        });
    });
});
