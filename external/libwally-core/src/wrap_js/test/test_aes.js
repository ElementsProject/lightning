var wally = require('../wally');
var test = require('tape');

var fs = require('fs');

if (require.extensions) {
  require.extensions['.txt'] = function (module, filename) {
    module.exports = fs.readFileSync(filename, 'utf8');
  };
}

var cbc_cases_input = require('../../data/aes-cbc-pkcs7.txt');
var cbc_lines = cbc_cases_input.split('\n').filter(
  function (l) { return (l.indexOf('#') != 0) && l.length; }
);

var cases = [
    // AES test vectors from FIPS 197.
    [ 128, "000102030405060708090a0b0c0d0e0f",
           "00112233445566778899aabbccddeeff",
           "69c4e0d86a7b0430d8cdb78070b4c55a" ],
    [ 192, "000102030405060708090a0b0c0d0e0f1011121314151617",
           "00112233445566778899aabbccddeeff",
           "dda97ca4864cdfe06eaf70a0ec0d7191" ],
    [ 256, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
           "00112233445566778899aabbccddeeff",
           "8ea2b7ca516745bfeafc49904b496089" ],
    // AES-ECB test vectors from NIST sp800-38a.
    [ 128, "2b7e151628aed2a6abf7158809cf4f3c",
           "6bc1bee22e409f96e93d7e117393172a",
           "3ad77bb40d7a3660a89ecaf32466ef97" ],
    [ 128, "2b7e151628aed2a6abf7158809cf4f3c",
           "ae2d8a571e03ac9c9eb76fac45af8e51",
           "f5d3d58503b9699de785895a96fdbaaf" ],
    [ 128, "2b7e151628aed2a6abf7158809cf4f3c",
           "30c81c46a35ce411e5fbc1191a0a52ef",
           "43b1cd7f598ece23881b00e3ed030688" ],
    [ 128, "2b7e151628aed2a6abf7158809cf4f3c",
           "f69f2445df4f9b17ad2b417be66c3710",
           "7b0c785e27e8ad3f8223207104725dd4" ],
    [ 192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
           "6bc1bee22e409f96e93d7e117393172a",
           "bd334f1d6e45f25ff712a214571fa5cc" ],
    [ 192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
           "ae2d8a571e03ac9c9eb76fac45af8e51",
           "974104846d0ad3ad7734ecb3ecee4eef" ],
    [ 192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
           "30c81c46a35ce411e5fbc1191a0a52ef",
           "ef7afd2270e2e60adce0ba2face6444e" ],
    [ 192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
           "f69f2445df4f9b17ad2b417be66c3710",
           "9a4b41ba738d6c72fb16691603c18e0e" ],
    [ 256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
           "6bc1bee22e409f96e93d7e117393172a",
           "f3eed1bdb5d2a03c064b5a7e3db181f8" ],
    [ 256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
           "ae2d8a571e03ac9c9eb76fac45af8e51",
           "591ccb10d410ed26dc5ba74a31362870" ],
    [ 256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
           "30c81c46a35ce411e5fbc1191a0a52ef",
           "b6ed21b99ca6f4f9f153e7b1beafed1d" ],
    [ 256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
           "f69f2445df4f9b17ad2b417be66c3710",
           "23304b7a39f9f3ff067d8d8f9e24ecc7" ],
];

test('AES ECB', function (t) {
  t.plan(cases.length * 2);
  cases.forEach(function(testCase) {
    var key = Buffer.from(testCase[1], 'hex');
    var plain = Buffer.from(testCase[2], 'hex');
    var cypher = Buffer.from(testCase[3], 'hex');
    var ENCRYPT = 1, DECRYPT = 2;
    wally.wally_aes(key, plain, ENCRYPT).then(function (d) {
      t.equal(Buffer.from(d).toString('hex'), cypher.toString('hex'),
        'aes encrypt('+plain.toString('hex')+')');
    });
    wally.wally_aes(key, cypher, DECRYPT).then(function (d) {
      t.equal(Buffer.from(d).toString('hex'), plain.toString('hex'),
        'aes decrypt('+cypher.toString('hex')+')');
    });
  });
});

test('AES CBC', function (t) {
  t.plan(cbc_lines.length / 4 * 2);  // encrypt+decrypt for each case (4 lines)

  for (var i = 0; i < cbc_lines.length / 4; ++i) {
    var plain = Buffer.from(cbc_lines[i * 4].split("=")[1], 'hex');
    var key = Buffer.from(cbc_lines[i * 4 + 1].split("=")[1], 'hex');
    var iv = Buffer.from(cbc_lines[i * 4 + 2].split("=")[1], 'hex');
    var cypher = Buffer.from(cbc_lines[i * 4 + 3].split("=")[1], 'hex');
    (function (plain, key, iv, cypher) {
      var ENCRYPT = 1, DECRYPT = 2;
      wally.wally_aes_cbc(key, iv, plain, ENCRYPT).then(function (d) {
        t.equal(Buffer.from(d).toString('hex'), cypher.toString('hex'),
          'aes CBC encrypt('+plain.toString('hex')+')');
      });
      wally.wally_aes_cbc(key, iv, cypher, DECRYPT).then(function (d) {
        t.equal(Buffer.from(d).toString('hex'), plain.toString('hex'),
          'aes CBC decrypt('+cypher.toString('hex')+')');
      });
    })(plain, key, iv, cypher);
   }
});
