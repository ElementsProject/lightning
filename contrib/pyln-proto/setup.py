
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


setup(name='pyln-proto',
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
      use_scm_version={
          "root": "../..",
          "relative_to": __file__,
          "write_to": "contrib/pyln-proto/pyln/proto/__version__.py",
          "write_to_template": "__version__ = \"{version}\"\n",
          "version_scheme": "post-release",
          "local_scheme": "no-local-version",
      },
      setup_requires=["setuptools_scm"],
      install_requires=requirements)
