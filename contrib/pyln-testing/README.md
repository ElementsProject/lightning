# pyln-testing: A library to write tests against Core Lightning

This library implements a number of utilities that help building tests for
Core Lightning nodes. In particular it provides a number of pytest fixtures that
allow the management of a test network of a given topology and then execute a
test scenarion.

`pyln-testing` is used by Core Lightning for its internal tests, and by the
community plugin directory to exercise the plugins.

## Installation

`pyln-testing` is available on `pip`:

```bash
pip install pyln-testing
```

Alternatively you can also install the development version to get access to
currently unreleased features by checking out the Core Lightning source code and
installing into your python3 environment:

```bash
git clone https://github.com/ElementsProject/lightning.git
cd lightning/contrib/pyln-testing
poetry install
```

This will add links to the library into your environment so changing the
checked out source code will also result in the environment picking up these
changes. Notice however that unreleased versions may change API without
warning, so test thoroughly with the released version.

## Testing GRPC Bindings

The grpc bindings can be tested by setting the `CLN_TEST_GRPC=1`
environment variable. This will cause the testing framework to use a
grpc client to talk to the `cln-grpc` plugin, rather than talking
directly to the node's JSON-RPC interface. Since the GRPC related
dependencies are guarded behind a feature flag in `pyln-testing`
you'll need to install it with the `grpc` feature enabled in order to
be able to run in this mode.

Below is a diagram of how the normal JSON-RPC interaction looks like,
followed by one that display the grpc interaction:

```
CLN -- JSON-RPC -- LightningRpc -- pytest
\_____CLN_____/    \_______pytest_______/
```

```
CLN -- JSON-RPC -- cln-rpc -- rpc2grpc converters -- grpc interface -- python grpc client -- python grpc2json converter -- pytest
\_____CLN_____/    \___________cln-grpc-plugin____________________/    \__________________________pytest________________________/
```

As you can see the grpc mode attempts to emulate the simple JSON-RPC
mode by passing the call through a number of conversions. The last
step `grpc2json` is rather incomplete, and will cause quite a few
tests to fail for now, until the conversion is completed and we reach
feature parity between the interaction modes.
