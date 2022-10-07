/* Test cases for invalid binding values/error mappings */
var wally = require('../wally');
var test = require('tape');

var undef;
var valid = Buffer.from('00CEF022FA', 'hex');
var h = function (h) { return Buffer.from(h, 'hex'); };
var vbf = h("8b5d87d94b9f54dc5dd9f31df5dffedc974fc4d5bf0d2ee1297e5aba504ccc26");
var generator = h("0ba4fd25e0e2108e55aec683810a8652f9b067242419a1f7cc0f01f92b4b078252");
var b38pass = Buffer.from('Satoshi', 'ascii');
var abfs = h("7fca161c2b849a434f49065cf590f5f1909f25e252f728dfd53669c3c8f8e37100000000000000000000000000000000000000000000000000000000000000002c89075f3c8861fea27a15682d664fb643bc08598fe36dcf817fcabc7ef5cf2efdac7bbad99a45187f863cd58686a75135f2cc0714052f809b0c1f603bcdc574");
var vbfs = h("1c07611b193009e847e5b296f05a561c559ca84e16d1edae6cbe914b73fb6904000000000000000000000000000000000000000000000000000000000000000074e4135177cd281b332bb8fceb46da32abda5d6dc4d2eef6342a5399c9fb3c48");

var cases = [
    [ function() { wally.wally_base58_from_bytes(null, 0); },
      /TypeError/, 'null const bytes' ],
    [ function() { wally.wally_base58_from_bytes(undef, 0); },
      /TypeError/, 'undefined const bytes' ],
    [ function() { wally.wally_base58_from_bytes(20, 0); },
      /TypeError/, 'non-buffer const bytes' ],
    /* FIXME: Argument count isn't checked yet
    [ function() { wally.wally_base58_from_bytes(); },
      /TypeError/, 'too few arguments' ],
    [ function() { wally.wally_base58_from_bytes(null, 0, 0); },
      /TypeError/, 'too many arguments' ],
       FIXME */
    [ function() { wally.wally_base58_from_bytes(valid, null); },
      /TypeError/, 'null uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, undef); },
      /TypeError/, 'undefined uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, -1); },
      /TypeError/, 'negative uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, 4294967296+1); },
      /TypeError/, 'overflow uint32_t' ],
    [ function() { wally.wally_base58_from_bytes(valid, valid); },
      /TypeError/, 'non-integer uint32_t' ],
    [ function() { wally.wally_asset_value_commitment(null, vbf, generator); },
      /TypeError/, 'null uint64_t' ],
    [ function() { wally.wally_asset_value_commitment(undef, vbf, generator); },
      /TypeError/, 'undefined uint64_t' ],
    [ function() { wally.wally_asset_value_commitment(10, vbf, generator); },
      /TypeError/, 'non-integer uint64_t' ],
    /* FIXME: These aren't actually testing the binding code, they are testing
     *        the wrapped output length calculation. We probably want tests
     *        for all functions wrapped in this way... */
    [ function() { wally.wally_base58_to_bytes(null, 0); },
      /TypeError/, 'null string' ],
    [ function() { wally.wally_base58_to_bytes(undef, 0); },
      /TypeError/, 'undefined string' ],
    /* End FIXME */
    [ function() { wally.bip38_to_private_key(null, b38pass, 0); },
      /TypeError/, 'null string' ],
    [ function() { wally.bip38_to_private_key(undef, b38pass, 0); },
      /TypeError/, 'undefined string' ],
    [ function() { wally.wally_asset_final_vbf(null, 1, abfs, vbfs); },
      /TypeError/, 'null uint64_t array' ],
    [ function() { wally.wally_asset_final_vbf(undef, 1, abfs, vbfs); },
      /TypeError/, 'undefined uint64_t array' ],
    [ function() { wally.wally_asset_final_vbf(1, 1, abfs, vbfs); },
      /TypeError/, 'non-array uint64_t array' ],
]

test('Bindings', function (t) {
    t.plan(cases.length);
    cases.forEach(function(testCase) {
        t.throws(testCase[0], testCase[1], testCase[2]);
    })
});
