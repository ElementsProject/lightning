"""setuptools config for wallycore """
from setuptools import setup
from setuptools import Distribution
import os
import subprocess
from distutils.command.build_clib import build_clib as _build_clib

class Distr(Distribution):
    def has_c_libraries(self):
        return True

class build_clib(_build_clib):
    def run(self):
        abs_path = os.path.dirname(os.path.abspath(__file__)) + '/'

        for cmd in ('./tools/autogen.sh',
                    './configure --enable-swig-python',
                    'make'):
            subprocess.check_call(cmd.split(' '), cwd=abs_path)

setup(
    name='wallycore',

    version='0.2.0',
    description='libwally Bitcoin library',
    long_description='Python bindings for the libwally Bitcoin library',
    url='https://github.com/jgriffiths/libwally-core',
    author='Jon Griffiths',
    author_email='jon_p_griffiths@yahoo.com',
    license='MIT',
    zip_safe=False,
    libraries=[('wallycore',{'sources':['include/wally_core.h']})],
    cmdclass={
        'build_clib': build_clib,
    },

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],

    keywords='Bitcoin wallet BIP32 BIP38 BIP39 secp256k1',

    packages=['wallycore'],
    package_dir={'':'src/swig_python'},
    data_files=[('', ['src/.libs/libwallycore.so'])] ,
)
