# pyln-proto: Lightning Network protocol implementation

This package implements some of the Lightning Network protocol in pure
python. It is intended for protocol testing and some minor tooling only. It is
not deemed secure enough to handle any amount of real funds (you have been
warned!).


## Installation

`pyln-proto` is available on `pip`:

```
pip install pyln-proto
```

Alternatively you can also install the development version to get access to
currently unreleased features by checking out the c-lightning source code and
installing into your python3 environment:

```bash
git clone https://github.com/ElementsProject/lightning.git
cd lightning/contrib/pyln-proto
python3 setup.py develop
```

This will add links to the library into your environment so changing the
checked out source code will also result in the environment picking up these
changes. Notice however that unreleased versions may change API without
warning, so test thoroughly with the released version.
