#! /usr/bin/env bash

if [ "$TRAVIS_OS_NAME" = "windows" ]; then
    SWIG_VERSION="4.0.1"
    choco install swig --version $SWIG_VERSION
    choco install python --version 3.7.4
    ln -sf /c/ProgramData/chocolatey/lib/swig/tools/install/swigwin-$SWIG_VERSION /c/swig

    export NVS_HOME=$ProgramData/nvs
    git clone --branch v1.5.3 --depth 1 https://github.com/jasongin/nvs $NVS_HOME
    source $NVS_HOME/nvs.sh
    nvs --version
    nvs add $NODE_VERSION
    nvs use $NODE_VERSION
    node --version
    npm --version
    npm i -g yarn

    sed -e 's/"defines": \[ "SWIG_JAVASCRIPT_BUILD", "HAVE_CONFIG_H" \]/"defines": \[ "SWIG_JAVASCRIPT_BUILD", "HAVE_CONFIG_H", "USE_ECMULT_STATIC_PRECOMPUTATION", "ECMULT_WINDOW_SIZE=15" \]/g' src/wrap_js/binding.gyp.tmpl > src/wrap_js/binding.gyp
fi
