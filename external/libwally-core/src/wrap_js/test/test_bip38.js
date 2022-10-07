var wally = require('../wally');
var test = require('tape');

var K_MAIN = 0,
    K_TEST = 7,
    K_COMP = 256,
    K_EC =  512,
    K_CHECK = 1024,
    K_RAW = 2048,
    K_ORDER =  4096;

// BIP38 Vectors from
// https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
cases = [
    [ 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
      Buffer.from('TestingOneTwoThree', 'ascii'),
      K_MAIN,
      '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg' ],
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      Buffer.from('Satoshi', 'ascii'),
      K_MAIN,
      '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq' ],
    [ '64EEAB5F9BE2A01A8365A579511EB3373C87C40DA6D2A25F05BDA68FE077B66E',
      Buffer.from('cf9300f0909080f09f92a9', 'hex'),
      K_MAIN,
      '6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn' ],
    [ 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
      Buffer.from('TestingOneTwoThree', 'ascii'),
      K_MAIN + K_COMP,
      '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo' ],
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      Buffer.from('Satoshi', 'ascii'),
      K_MAIN + K_COMP,
      '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7' ],
    // Raw vectors:
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      Buffer.from('Satoshi', 'ascii'),
      K_MAIN + K_COMP + K_RAW,
      '0142E00B76EA60B62F66F0AF93D8B5380652AF51D1A3902EE00726CCEB70CA636B5B57CE6D3E2F' ],
    [ '3CBC4D1E5C5248F81338596C0B1EE025FBE6C112633C357D66D2CE0BE541EA18',
      Buffer.from('jon', 'ascii'),
      K_MAIN + K_COMP + K_RAW + K_ORDER,
      '0142E09F8EE6E3A2FFCB13A99AA976AEDA5A2002ED3DF97FCB9957CD863357B55AA2072D3EB2F9' ],
];

test('BIP38', function(t) {
  t.plan(cases.length * 2);

  cases.forEach(function (c) {
    var priv_key = Buffer.from(c[0], 'hex');
    var passwd = c[1];
    var flags = c[2];
    var expected = c[3];

    var fun_from_priv, fun_to_priv;
    if (flags > K_RAW) {
      fun_from_priv = wally.bip38_raw_from_private_key.bind(wally);
      fun_to_priv = wally.bip38_raw_to_private_key.bind(wally);
    } else {
      fun_from_priv = wally.bip38_from_private_key.bind(wally);
      fun_to_priv = wally.bip38_to_private_key.bind(wally);
    }

    fun_from_priv(priv_key, passwd, flags).then(function (res) {
      if (flags > K_RAW) {
        t.equal(Buffer.from(res).toString('hex'), expected.toLowerCase(),
          'bip38_raw_from_priv('+priv_key.toString('hex')+')');
      } else {
        t.equal(res, expected, 'bip38_from_priv('+priv_key.toString('hex')+')');
      }
    });

    var expectedForToPriv;
    if (flags > K_RAW) {
       expectedForToPriv = Buffer.from(expected, 'hex');
    } else {
       expectedForToPriv = expected;
    }
    fun_to_priv(expectedForToPriv, passwd, flags).then(function (res) {
      t.equal(Buffer.from(res).toString('hex'), priv_key.toString('hex'),
        'bip38 to priv('+expected+')');
    });
  });
});
