var wally = require('../wally');
var test = require('tape');

var cases = [];
// Leading zeros become ones
for (var i = 1; i < 10; ++i) {
  var ones = '';
  for (var j = 0; j < i; ++j) ones += '1';
  cases.push([[new Uint8Array(i), 0], ones])
}
cases.push([[Buffer.from('00CEF022FA', 'hex'), 0], '16Ho7Hs']);
cases.push([[Buffer.from('45046252208D', 'hex'), 1], '4stwEBjT6FYyVV']);

test('base58 from bytes', function (t) {
  t.plan(cases.length);
  cases.forEach(function(testCase) {
    wally.wally_base58_from_bytes(
      testCase[0][0], testCase[0][1]
    ).then(function(s) {
      t.equal(s, testCase[1],
        'base58_from_bytes('+
        Buffer.from(testCase[0][0]).toString('hex')+','+testCase[0][1]+')');
    });
  });
});

test('base58 to bytes', function (t) {
  /* [TODO:]
  # Bad input base58 strings
  for bad in [ '',        # Empty string can't be represented
               '0',       # Forbidden ASCII character
               'x0',      # Forbidden ASCII character, internal
               '\x80',    # High bit set
               'x\x80x',  # High bit set, internal
             ]:
      ret, _ = wally_base58_to_bytes(utf8(bad), 0, buf, buf_len)
      self.assertEqual(ret, WALLY_EINVAL

  # Bad checksummed base58 strings
  for bad in [ # libbase58: decode-b58c-fail
              '19DXstMaV43WpYg4ceREiiTv2UntmoiA9a',
              # libbase58: decode-b58c-toolong
              '1119DXstMaV43WpYg4ceREiiTv2UntmoiA9a',
              # libbase58: decode-b58c-tooshort
              '111111111111111111114oLvT2']:
      ret, _ = wally_base58_to_bytes(utf8(bad), self.FLAG_CHECKSUM, buf, buf_len)
      self.assertEqual(ret, WALLY_EINVAL))


  for base58 in ['BXvDbH', '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM']:
      ret, out_len = wally_base58_get_length(utf8(base58))
      # Output buffer too small returns OK and the number of bytes required
      ret, bin_len = wally_base58_to_bytes(utf8(base58), 0, buf, out_len - 1)
      self.assertEqual((ret, bin_len), (WALLY_OK, out_len))
      # Unknown flags
      ret, _ = wally_base58_to_bytes(utf8(base58), 0x7, buf, buf_len)
      self.assertEqual(ret, WALLY_EINVAL)

  # If we ask for checksum validation/removal the output buffer
  # must have room for a checksum.
  ret, bin_len = wally_base58_to_bytes(utf8('1'), self.FLAG_CHECKSUM,
                                       buf, self.CHECKSUM_LEN)
  self.assertEqual(ret, WALLY_EINVAL)

  base58 = '93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T'
  ret = self.decode(base58, self.FLAG_CHECKSUM)
  expected = 'EFFB309E964684B54E6069F146E2CD6DA' \
             'E936B711A7A98DF4097156B9FC9B344EB'
  self.assertEqual(ret, utf8(expected))
  var cases = [];

  for (var i = 0; i < 10; ++i) {
      var ones = '';
      for (var j = 0; j < i; ++j) ones += '1';
      cases.push([[new Uint8Array(i), 0], ones])
      self.assertEqual(self.decode('1' * i, 0), utf8('00' * i))

  # Vectors from https://github.com/bitcoinj/bitcoinj/
  self.assertEqual(self.decode('16Ho7Hs', 0), utf8('00CEF022FA'))
  self.assertEqual(self.decode('4stwEBjT6FYyVV', self.FLAG_CHECKSUM),
                               utf8('45046252208D')) */

  t.plan(cases.length);
  cases.forEach(function(testCase) {
    wally.wally_base58_to_bytes(
      testCase[1], testCase[0][1]
    ).then(function(d) {
      t.equal(Buffer.from(d).toString('hex'),
      Buffer.from(testCase[0][0]).toString('hex'),
        'base58_to_bytes('+testCase[1]+','+testCase[0][1]+')');
    });
  });
});
