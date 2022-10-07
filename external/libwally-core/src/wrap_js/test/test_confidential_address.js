const wally = require('../wally');
const test = require('tape');

test('Confidential Address', function(t) {
    t.plan(3);

    // The (Liquid) address that is to be blinded
    addr = 'Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6';
    // The blinding pubkey
    pubkey_hex = '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623';
    // The resulting confidential address
    addr_c = 'VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK';

    // Test we can extract the original address
    wally.wally_confidential_addr_to_addr(addr_c, wally.WALLY_CA_PREFIX_LIQUID).then((res) => {
        t.equal(res, addr, 'Conf addr to addr');
    });

    // Test we can extract the blinding pubkey then re-generate the confidential address from its inputs
    wally.wally_confidential_addr_to_ec_public_key(addr_c, wally.WALLY_CA_PREFIX_LIQUID).then((ecpubkey) => {
        t.equal(Buffer.from(ecpubkey).toString('hex'), pubkey_hex, 'Extract blinding key');
        wally.wally_confidential_addr_from_addr(addr, wally.WALLY_CA_PREFIX_LIQUID, ecpubkey).then((res) => {
            t.equal(res, addr_c, 'Addr to conf addr');
        });   
    });
});
