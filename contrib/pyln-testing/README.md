# pyln-testing: A library to write tests against c-lightning

This library implements a number of utilities that help building tests for
c-lightning nodes. In particular it provides a number of pytest fixtures that
allow the management of a test network of a given topology and then execute a
test scenarion.

`pyln-testing` is used by c-lightning for its internal tests, and by the
community plugin directory to exercise the plugins.

## Installation

`pyln-testing` is available on `pip`:

```bash
pip install pyln-testing
```

Alternatively you can also install the development version to get access to
currently unreleased features by checking out the c-lightning source code and
installing into your python3 environment:

```bash
git clone https://github.com/ElementsProject/lightning.git
cd lightning/contrib/pyln-testing
python3 setup.py develop
```

This will add links to the library into your environment so changing the
checked out source code will also result in the environment picking up these
changes. Notice however that unreleased versions may change API without
warning, so test thoroughly with the released version.

