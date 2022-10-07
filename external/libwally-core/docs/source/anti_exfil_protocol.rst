Anti-Exfil Protocol
====================

.. _anti-exfil-protocol:

The following walkthrough demonstrates how to use libwally to implement the
ECDSA Anti-Exfil Protocol to prevent a signing device from exfiltrating the
secret signing keys through biased signature nonces.
For the full details, see
`here <https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/include/secp256k1_ecdsa_s2c.h#L100-L155>`_.

The example code here is written in python using the generated python swig
wrappers.

Step 1
------

The host draws randomness ``rho`` and computes a commitment to it:

.. literalinclude:: ../../src/pyexample/anti-exfil.py
    :start-after: start-step-1
    :end-before: end-step-1

Host sends ``host_commitment`` to the signer.

Step 2
------

The signing device computes the original nonce ``R``, i.e. ``signer commitment``:

.. literalinclude:: ../../src/pyexample/anti-exfil.py
    :start-after: start-step-2
    :end-before: end-step-2

Signing device sends ``signer_commitment`` to the host.

.. warning::
    If, at any point from this step onward, the hardware device fails, it is
    okay to restart the protocol using **exactly the same** ``rho`` and checking
    that the hardware device proposes **exactly the same** ``R``. Otherwise, the
    hardware device may be selectively aborting and thereby biasing the set of
    nonces that are used in actual signatures.

    It takes many (>100) such aborts before there is a plausible attack, given
    current knowledge in 2020. However such aborts accumulate even across a total
    replacement of all relevant devices (but not across replacement of the actual
    signing keys with new independently random ones).

    In case the hardware device cannot be made to sign with the given ``rho``, ``R``
    pair, wallet authors should alert the user and present a very scary message
    implying that if this happens more than even a few times, say 20 or more times
    EVER, they should change hardware vendors and perhaps sweep their coins.

Step 3
------

The host replies with ``rho`` generated at `Step 1`_.

Step 4
------

The signing device signs and provide the signature to the host:

.. literalinclude:: ../../src/pyexample/anti-exfil.py
    :start-after: start-step-4
    :end-before: end-step-4

Step 5
------

The host verifies that the signature's public nonce matches the signer
commitment ``R`` from `Step 2`_ and its original randomness ``rho``:

.. literalinclude:: ../../src/pyexample/anti-exfil.py
    :start-after: start-step-5
    :end-before: end-step-5
