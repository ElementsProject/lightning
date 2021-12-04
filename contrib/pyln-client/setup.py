from setuptools import setup
import io


with io.open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]


setup(name='pyln-client',
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
      use_scm_version={
          "root": "../..",
          "relative_to": __file__,
          "write_to": "contrib/pyln-client/pyln/client/__version__.py",
          "write_to_template": "__version__ = \"{version}\"\n",
          "version_scheme": "post-release",
          "local_scheme": "no-local-version",
      },
      setup_requires=["setuptools_scm"],
      install_requires=requirements)
