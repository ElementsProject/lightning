REM You need to set SWIG_PATH to the location where the swig zip
REM file is expanded to
%SWIG_PATH%\swig -python -Isrc -I%SWIG_PATH%\Lib\python -DBUILD_ELEMENTS=1 src\swig_python\swig.i
copy src\swig_python\wallycore.py + src\swig_python\python_extra.py_in src\swig_python\wallycore\__init__.py /B
del src\swig_python\wallycore.py
