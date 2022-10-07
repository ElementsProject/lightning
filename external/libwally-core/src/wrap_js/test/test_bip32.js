const wally = require('../wally');
const test = require('tape');
const seed = Buffer.from('00000000000000000000000000000000', 'hex');

test('BIP32 from seed + derivation', function(t) {
  t.plan(6);

  wally.bip32_key_from_seed(Buffer.from(seed), wally.BIP32_VER_MAIN_PRIVATE, wally.BIP32_FLAG_KEY_PRIVATE).then(function(s) {
    wally.wally_base58_from_bytes(s, wally.BASE58_FLAG_CHECKSUM).then(function (s) {
      t.equal(
        s,
        ('xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7Q'+
         'jMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta'),
        'privkey'
      );
    });

    wally.bip32_pubkey_from_parent(s, 1, wally.BIP32_FLAG_KEY_PRIVATE).then(function (pub) {
      wally.wally_base58_from_bytes(pub, wally.BASE58_FLAG_CHECKSUM).then(function (s) {
        t.equal(
          s,
          ('xpub683nVy7Tt7baCKuqho7X5C7TGuskZAa4wQ5YEue2BxtYB6upN4Yg'+
           'WTyZYnLg56XDFt7YN3DrFZEYmEhMqpsZmiP73NNrR5P8WcbfWgfQGGi'),
          'pubkey'
        );
      });
    });

    wally.bip32_key_get_priv_key(s).then(function(privkey) {
      wally.wally_ec_public_key_from_private_key(privkey).then(function(master_pubkey) {
        t.equal(
          Buffer.from(master_pubkey).toString('hex'),
          '02be99138b48b430a8ee40bf8b56c8ebc584c363774010a9bfe549a87126e61746',
          'm->pub'
        );
      });
    })

    wally.bip32_privkey_from_parent(s, 0, wally.BIP32_FLAG_KEY_PRIVATE).then(function (xpriv_0) {
      wally.wally_base58_from_bytes(xpriv_0, wally.BASE58_FLAG_CHECKSUM).then(function (base58_xpriv) {
        t.equal(
          base58_xpriv,
          'xprv9u4S6Taa3k3GxnaHfWzboKwLPPPHpDyDHdLGqDArBejguBuv6GkerLy6MtAeFfo9RDfZy22FWEc1ExEShuRGZJpgVgeVu5KZ5obWbV2R3D2',
          'm/0'
        );
      });
    });

    wally.bip32_pubkey_from_parent(s, 0, wally.BIP32_FLAG_KEY_PRIVATE).then(function (xpub_0) {
      wally.wally_base58_from_bytes(xpub_0, wally.BASE58_FLAG_CHECKSUM).then(function (base58_xpub) {
        t.equal(
          base58_xpub,
          'xpub683nVy7Tt7baBGekmYXcATt4wRDnDgh4erFsdbaTjzGfmzF4dp4uQ9HaDCdvSqctrsbxZey5wozKyyy2J3zhDDHU3UhW4uCFQp6bESv8ewQ',
          'M/0'
        );
      });

      wally.bip32_pubkey_from_parent(xpub_0, 1, wally.BIP32_FLAG_KEY_PUBLIC).then(function (xpub_0_1) {
        wally.wally_base58_from_bytes(xpub_0_1, wally.BASE58_FLAG_CHECKSUM).then(function (base58_xpub) {
          t.equal(
            base58_xpub,
            'xpub6An6e2ai6kSDnnxJ3876JwfeigdQu9YNudcP7ayT828xDFzFQkP9oBoBNdvj7xDrDQd9TQDpzkLhM5L71rFDTmxMuzSvXwZKnLx56Es6MEg',
            'M/0/1'
          );
        });
      });
    });
  });
});

test('BIP32 from seed to address', function(t) {
  t.plan(1);

  wally.bip32_key_from_seed(seed, wally.BIP32_VER_MAIN_PRIVATE, wally.BIP32_FLAG_KEY_PRIVATE).then(function(s) {
    return wally.bip32_pubkey_from_parent(s, 0, wally.BIP32_FLAG_KEY_PUBLIC);
  }).then((xpubkey) => {
    return wally.bip32_key_get_pub_key(xpubkey);
  }).then((pubkey) => {
    return wally.wally_hash160(pubkey);
  }).then((script) => {
    const prefix = Buffer.from('eb', 'hex');
    return wally.wally_base58_from_bytes(Buffer.concat([prefix, Buffer.from(script)]), wally.BASE58_FLAG_CHECKSUM);
  }).then((address) => {
    t.equal(
      address,
      '2dmvtD27wpRyLK79FsAidyS33uUogsYNC4U',
      'address'
    );
  });
});
