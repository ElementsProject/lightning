Liquid
======

The following walkthrough demonstrates how to use libwally to create a
transaction spending a confidential liquid utxo. For documentation of
the Blockstream Liquid network please go to
`Blockstream <https://docs.blockstream.com>`_

The example code here is written in python using the generated python
swig wrappers.

Generating a confidential address
---------------------------------

Start by creating a standard p2pkh address. Assume that we have defined
``mnemonic`` as a 24 word mnemonic for the wallet we want to use. From this we
can derive bip32 keys depending on the requirements of the wallet.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-create_p2pkh_address
    :end-before: end-create_p2pkh_address

For each new receive address a blinding key should be deterministically
derived from a master blinding key, itself derived from the bip39
mnemonic for the wallet. wally provides the function
:c:func:`wally_asset_blinding_key_from_seed` which can be used to derive a master
blinding key from a mnemonic.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-derive_blinding_key
    :end-before: end-derive_blinding_key

Finally call the wally function :c:func:`wally_confidential_addr_from_addr` to combine
the non-confidential address with the public blinding key to create a
confidential address. We also supply a blinding prefix indicating the
network version.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-create_conf_address
    :end-before: end-create_conf_address

The confidential address can now be passed to liquid-cli to receive
funds. We'll send 1.1 BTC to our confidential address and save the raw
hex transaction for further processing.

.. code-block:: bash

    $ liquid-cli getrawtransaction $(sendtoaddress <confidential address> 1.1)

Receiving confidential assets
-----------------------------

On receiving confidential (blinded) utxos you can use libwally to
unblind and inspect them. Take the hex transaction returned by
getrawtransaction above and create a libwally tx.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-create_tx
    :end-before: end-create_tx

The transaction will likely have three outputs: the utxo paying to our
confidential address, a change output and an explicit fee output(Liquid
transactions differ from standard bitcoin transaction in that the fee is
an explicit output). Iterate over the transaction outputs and unblind any
addressed to us.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-unblind
    :end-before: end-unblind

We have now unblinded the values and asset ids of the utxos. We've also
saved the abfs (asset blinding factors) and vbfs (value binding factors)
because they are needed for the next step: spending the utxos.

Spending confidential assets
----------------------------

The wallet logic will define the transaction outputs, values and fees. Here we
assume that we're only dealing with a single asset and a single confidential
recipient address ``destination_address`` to which we'll pay the input amount
less some fixed ``fee``.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-define_outputs
    :end-before: end-define_outputs

Generate blinding factors for the outputs. These are asset blinding
factors (abf) and value blinding factors (vbf). The blinding factors are
random except for the final vbf which must be calculated by calling
:c:func:`wally_asset_final_vbf`.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-blinding_factors
    :end-before: end-blinding_factors

A confidential output address can be decomposed into a standard address
plus the public blinding key, and the libwally function
:c:func:`wally_address_to_scriptpubkey` will provide the corresponding script pubkey.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-decompose_address
    :end-before: end-decompose_address

Create a new transaction

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-create_output_tx
    :end-before: end-create_output_tx

Iterate over the outputs and calculate the value commitment, rangeproof
and surjectionproofs. This requires generating a random ephemeral
public/private ec key pair for each blinded output.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-create_outputs
    :end-before: end-create_outputs

Finally the fee output must be explicitly added (unlike standard Bitcoin
transactions where the fee is implicit). The fee is always payable in
the bitcoin asset. The wallet logic will determine the fee amount.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-add_fee
    :end-before: end-add_fee

Sign the transaction inputs.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-sign
    :end-before: end-sign

The transaction is now ready to be broadcast, the hex value is easily
retrieved by calling :c:func:`wally_tx_to_hex`.

.. literalinclude:: ../../src/pyexample/liquid/receive-send.py
    :start-after: start-to_hex
    :end-before: end-to_hex
