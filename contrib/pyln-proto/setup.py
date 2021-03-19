
from setuptools import setup
import codecs
import io
import os.path


with io.open('README.md', encoding='utf-8') as f:
    long_description = f.read()


with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()


def get_version(rel_path):
    for line in read(rel_path).splitlines():
        if line.startswith('__version__'):
            delim = '"' if '"' in line else "'"
            return line.split(delim)[1]
    else:
        raise RuntimeError("Unable to find version string.")


setup(name='pyln-proto',
      version=get_version("pyln/proto/__init__.py"),
      description='Pure python implementation of the Lightning Network protocol',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='http://github.com/ElementsProject/lightning',
      author='Christian Decker',
      author_email='decker.christian@gmail.com',
      license='MIT',
      packages=['pyln.proto', 'pyln.proto.message'],
      package_data={'pyln.proto.message': ['py.typed']},
      scripts=[],
      zip_safe=True,
      install_requires=requirements)
