REM Set VS 2017 environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\Tools\VsDevCmd.bat"

REM Need to first build gen_context.exe to generate a header file
REM It seems possible to skip this step and remove the definition
REM of USE_ECMULT_STATIC_PRECOMPUTATION  from the compiler flags
set LIBWALLY_DIR=%cd%
call "%~dp0\gen_ecmult_static_context.bat" || echo ERRORGENCONTEXT && exit /b 1

REM Create wrappers for wallyjs node module
REM Elements build is 'set ELEMENTS_BUILD="elements"'.
cd src
python wrap_js/makewrappers/wrap.py wally Release %ELEMENTS_BUILD%
python wrap_js/makewrappers/wrap.py nodejs Release %ELEMENTS_BUILD%
if "%ELEMENTS_BUILD%" == "elements" (
  copy /Y /B wrap_js\windows_config\binding.gyp.elements_tmpl wrap_js\binding.gyp /B
) else (
  copy /Y /B wrap_js\windows_config\binding.gyp.tmpl wrap_js\binding.gyp /B
)

REM Install wallyjs
cd wrap_js

call yarn install
