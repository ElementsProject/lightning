REM Run swig to generate the wrapper source files required by
REM setup.py build step
call "%~dp0"\swig.bat || echo ERRORSWIG && exit /b 1

REM Set VS 2017 environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\Tools\VsDevCmd.bat"

REM Need to first build gen_context.exe to generate a header file
REM It seems possible to skip this step and remove the definition
REM of USE_ECMULT_STATIC_PRECOMPUTATION  from the compiler flags
set LIBWALLY_DIR=%cd%
call "%~dp0\gen_ecmult_static_context.bat" || echo ERRORGENCONTEXT && exit /b 1
