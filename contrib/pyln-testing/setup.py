from setuptools import setup
from pyln.testing import __version__


with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt', 'r') as f:
    requirements = [l.strip() for l in f]

setup(name='pyln-testing',
      version=__version__,
      description='Library to facilitate writing tests for for lightningd',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='http://github.com/ElementsProject/lightning',
      author='Christian Decker',
      author_email='decker.christian@gmail.com',
      install_requires=requirements,
      license='MIT',
      packages=['pyln.testing'],
      zip_safe=True)
