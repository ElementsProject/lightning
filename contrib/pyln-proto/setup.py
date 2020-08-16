from setuptools import setup
import io


with io.open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with io.open('requirements.txt', encoding='utf-8') as f:
    requirements = [r for r in f.read().split('\n') if len(r)]

setup(name='pyln-proto',
      version='0.8.3',
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
