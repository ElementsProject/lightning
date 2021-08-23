from setuptools import setup
import io
import os

base = os.path.dirname(__file__)
with io.open(os.path.join(base, 'requirements.txt'), encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]


def bolt_meta(bolt_num):
    ctx = {}
    pkg_dir = os.path.join(base, 'pyln', 'spec', 'bolt{}'.format(bolt_num))

    files = ['gen_version.py', 'gen_csv_version.py', 'text.py']

    for f in files:
        f = os.path.join(pkg_dir, f)
        with open(f, 'r') as fd:
            exec(fd.read(), ctx)

    __version__ = '{__base_version__}.{__csv_version__}.{__post_version__}'.format(**ctx)
    return {
        'description': ctx['desc'],
        'version': __version__,
    }


def bolt_num():
    """Look into the pyln/spec/ directory to see which subpackages we provide.
    """
    dirlist = os.listdir(os.path.join('pyln', 'spec'))
    assert(len(dirlist) == 1)  # Should only be the boltX directory
    b = dirlist[0]
    assert(b[:4] == 'bolt')
    return int(b[4])


boltnum = bolt_num()
meta = bolt_meta(boltnum)

setup(
    **meta,
    name='pyln-bolt{}'.format(boltnum),
    url='http://github.com/ElementsProject/lightning',
    author='Rusty Russell',
    author_email='rusty@rustcorp.com.au',
    license='MIT',
    packages=['pyln.spec.bolt{}'.format(boltnum)],
    package_data={'pyln.proto.message': ['py.typed']},
    scripts=[],
    zip_safe=True,
    install_requires=requirements
)
