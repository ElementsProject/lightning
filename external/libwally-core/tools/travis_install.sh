#!/bin/sh

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    brew update
    brew install gnu-sed
    brew install swig
fi
