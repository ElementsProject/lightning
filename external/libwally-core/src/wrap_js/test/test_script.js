const wally = require('../wally');
const test = require('tape');

const pubkeys = [
    '02ad4199d0c53b564b39798c4c064a6e6093abbb71d56cc153abf75a02f85c8e99',
    '03afeefeba0806711b6d3fc7c8b0b6a3eff5ea2ecf938aea1b6a093898097875f3'
];

test('Script', function(t) {
    t.plan(1);

    const pubkey_bytes = Buffer.from(pubkeys[0] + pubkeys[1], 'hex');
    const redeem_script = '522102ad4199d0c53b564b39798c4c064a6e6093abbb71d56cc153abf75a02f85c8e992103afeefeba0806711b6d3fc7c8b0b6a3eff5ea2ecf938aea1b6a093898097875f352ae';

    wally.wally_scriptpubkey_multisig_from_bytes(
        pubkey_bytes,
        2,
        0,
        (pubkey_bytes.byteLength / wally.EC_PUBLIC_KEY_LEN) * 34 + 3
    ).then((res) => {
        t.equal(Buffer.from(res).toString('hex'), redeem_script);
    });
});
