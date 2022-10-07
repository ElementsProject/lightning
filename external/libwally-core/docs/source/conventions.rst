Library Conventions
===================

.. _error-codes:

Error Codes
-----------

The following values can be returned by library functions:

================ =============================================
Code             Meaning
================ =============================================
``WALLY_OK``     The function completed without error.
                 See :ref:`variable-length-output-buffers` if
                 applicable for the function.
``WALLY_ERROR``  An internal or unexpected error happened in
                 the library. In some cases this code may
                 indicate a specific error condition which
                 will be documented with the function.
``WALLY_EINVAL`` One or more parameters passed to the function
                 is not valid. For example, a required buffer
                 value is NULL or of the wrong length.
``WALLY_ENOMEM`` The function required memory allocation but
                 no memory could be allocated from the O/S.
================ =============================================


.. _variable-length-output-buffers:

Variable Length Output Buffers
------------------------------

Some functions write output that can vary in length to user supplied buffers.
In these cases, the number of written bytes is placed in the ``written``
output parameter when the function completes.

If the user supplied buffer is of insufficient size, these functions will
still return ``WALLY_OK``, but will place the required size in the ``written``
output parameter.

Callers must check not only that the function succeeds, but also that the
number of bytes written is less than or equal to the supplied buffer size.
If the buffer is too small, it should be resized to the returned size and the
call retried.
