var wally = require('../wally');
var test = require('tape');

var valid_cases = [];
valid_cases.push(['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc', 0, '0014751e76e8199196d454941c45d1b3a323f1433bd6']);
valid_cases.push(['tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 'tb', 0, '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262']);
valid_cases.push(['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', 'bc', 1, '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6']);
valid_cases.push(['BC1SW50QGDZ25J', 'bc', 16, '6002751e']);
valid_cases.push(['bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', 'bc', 2, '5210751e76e8199196d454941c45d1b3a323']);
valid_cases.push(['tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy', 'tb', 0, '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433']);
valid_cases.push(['tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c', 'tb', 1, '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433']);
valid_cases.push(['bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 'bc', 1, '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798']);

// witness version != 0
var fail_cases = [];
// https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
fail_cases.push(['tb', 'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty']); // Invalid human-readable part
fail_cases.push(['bc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5']); // Invalid checksum
fail_cases.push(['bc', 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2']); // Invalid witness version
fail_cases.push(['bc', 'bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ss52r5n8']); // Invalid witness version v1
fail_cases.push(['bc', 'bc1rw5uspcuh']); // Invalid program length
fail_cases.push(['bc', 'bc1pw5dgrnzv']); // Invalid program length
fail_cases.push(['tb', 'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut']); // Invalid HRP
fail_cases.push(['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd']); // Invalid checksum algorithm (bech32 instead of bech32m)
fail_cases.push(['tb', 'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf']); // Invalid checksum algorithm (bech32 instead of bech32m)
fail_cases.push(['bc', 'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL']); // Invalid checksum algorithm (bech32m instead of bech32)
fail_cases.push(['bc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh']); // Invalid checksum algorithm (bech32m instead of bech32)
fail_cases.push(['tb', 'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47']); // Invalid checksum algorithm (bech32m instead of bech32)
fail_cases.push(['bc', 'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4']); // Invalid character in checksum
fail_cases.push(['bc', 'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R']); // Invalid witness version
fail_cases.push(['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav']); // Invalid program length (41 bytes)
fail_cases.push(['bc', 'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90']); // Invalid program length
fail_cases.push(['bc', 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P']); // Invalid program length for witness version 0 (per BIP141)
fail_cases.push(['tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7']); // Mixed case
fail_cases.push(['bc', 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du']); // zero padding of more than 4 bits
fail_cases.push(['tb', 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq']); // Mixed case
fail_cases.push(['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf']); // more than 4 bit padding
fail_cases.push(['tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv']); // Non-zero padding in 8-to-5 conversion
fail_cases.push(['tb', 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j']); // Non-zero padding in 8-to-5 conversion
fail_cases.push(['bc', 'bc1gmk9yu']); // Empty data section
fail_cases.push(['bc', 'BC1SW50QA3JX3S']); // Invalid checksum
fail_cases.push(['bc', 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj']); // Invalid checksum
// https://blockstream.info/address/bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx
fail_cases.push(['bc', 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx']); // V > 0 must be bech32m

test('addr segwit to bytes', function (t) {
  var flags = 0;
  t.plan(2 * valid_cases.length + 2 * fail_cases.length);
  valid_cases.forEach(function(testCase) {
    wally.wally_addr_segwit_to_bytes(
      testCase[0], testCase[1], flags
    ).then(function(d) {
      t.equal(Buffer.from(d).toString('hex'),
      testCase[3],
        'addr_segwit_to_bytes('+testCase[0]+','+testCase[1]+')');
    })
  });

  valid_cases.forEach(function(testCase) {
    wally.wally_addr_segwit_from_bytes(
      Buffer.from(testCase[3], 'hex'), testCase[1], flags
    ).then(function(d) {
      t.equal(d.toLowerCase(), testCase[0].toLowerCase(),
        'addr_segwit_from_bytes('+testCase[3]+','+testCase[1]+')');
    })
  });

  fail_cases.forEach(function(testCase) {
    t.throws(function() {
      wally.wally_addr_segwit_to_bytes(testCase[0], testCase[1], 0);
    }, /TypeError/);
  });

  fail_cases.forEach(function(testCase) {
    t.throws(function() {
      wally.wally_addr_segwit_from_bytes(Buffer.from(testCase[3], 'hex'), testCase[1], 0);
    }, /TypeError/);
  });
});
