from pyln.spec.bolt7 import __version__, desc
from setuptools import setup
import io

with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]


def do_setup(boltnum: int, version: str, desc: str):
    setup(name='pyln-bolt{}'.format(boltnum),
          version=version,
          description=desc,
          url='http://github.com/ElementsProject/lightning',
          author='Rusty Russell',
          author_email='rusty@rustcorp.com.au',
          license='MIT',
          packages=['pyln.spec.bolt{}'.format(boltnum)],
          package_data={'pyln.proto.message': ['py.typed']},
          scripts=[],
          zip_safe=True,
          install_requires=requirements)


do_setup(7, __version__, desc)
