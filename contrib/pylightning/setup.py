from setuptools import setup

setup(name='pylightning',
      version='0.0.3',
      description='Client library for lightningd',
      url='http://github.com/ElementsProject/lightning',
      author='Christian Decker',
      author_email='decker.christian@gmail.com',
      license='MIT',
      packages=['lightning'],
      scripts=['lightning-pay'],
      zip_safe=True)
