from setuptools import setup
import io


with io.open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]

# setup shouldn't try to load module, so we hack-parse __init__.py
with io.open('pyln/client/__init__.py', encoding='utf-8') as f:
    for line in f.read().split('\n'):
        if line.startswith('__version__ = "'):
            version = line.split('"')[1]

setup(name='pyln-client',
      version=version,
      description='Client library for lightningd',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='http://github.com/ElementsProject/lightning',
      author='Christian Decker',
      author_email='decker.christian@gmail.com',
      license='MIT',
      packages=['pyln.client'],
      scripts=[],
      zip_safe=True,
      install_requires=requirements)
