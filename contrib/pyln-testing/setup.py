from setuptools import setup


with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt', 'r') as f:
    requirements = [l.strip() for l in f]

setup(name='pyln-testing',
      description='Library to facilitate writing tests for for lightningd',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='http://github.com/ElementsProject/lightning',
      author='Christian Decker',
      author_email='decker.christian@gmail.com',
      install_requires=requirements,
      license='MIT',
      packages=['pyln.testing'],
      use_scm_version={
          "root": "../..",
          "relative_to": __file__,
          "write_to": "contrib/pyln-testing/pyln/testing/__version__.py",
          "write_to_template": "__version__ = \"{version}\"\n",
          "version_scheme": "post-release",
          "local_scheme": "no-local-version",
      },
      setup_requires=["setuptools_scm"],
      zip_safe=True)
