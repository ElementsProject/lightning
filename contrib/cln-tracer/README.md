# cln-tracer

Utilities to export USDT traces from CLN.

This directory contains the following utilities:

 - `cln_tracer/trace.py` instruments and exports traces from a single binary.

## Prerequisites

`trace.py` sends traces to [zipkin](https://zipkin.io/), so zipkin needs to be
installed.

## Installation

Since the `bcc` library depends heavily on its binary extension
matching the version of the kernel `systemtap-sdt-dev` version, it is
strongly suggested to install the `libbpfcc` dependency via your
package manager and _not_ use a virtualenv to run these tracers.

The tracers also require kernel access, and will most likely have to
be run by `root`

## Usage
To use with a default zipkin installation:
```bash
sudo python3 ./cln_tracer/trace.py http://127.0.0.1:9411/api/v2/spans /path/to/lightningd`
```