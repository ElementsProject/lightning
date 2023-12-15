# cln-tracer

Utilities to export USDT traces from CLN.

This directory contains the following utilities:

 - `cln_tracer/trace.py` instruments and exports traces from a single binary.

## Installation

Since the `bcc` library depends heavily on its binary extension
matching the version of the kernel `systemtap-sdt-dev` version, it is
strongly suggested to install the `libpbfcc` dependency via your
package manager and _not_ use a virtualenv to run these tracers.

The tracers also require kernel access, and will most likely have to
be run by `root`
