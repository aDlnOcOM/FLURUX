@echo off
setlocal
rem Run from the x64 Native Tools Command Prompt for Visual Studio 2022.
pushd "%~dp0"
if not exist "build" mkdir "build"
cl /nologo /std:c++17 /O2 /EHsc /W4 /MT /guard:cf /DUNICODE /D_UNICODE /Fe:build\FluruxGuard.exe /Fo:build\FluruxGuard.obj guard.cpp /link /Brepro /DEPENDENTLOADFLAG:0x800 /DYNAMICBASE /NXCOMPAT advapi32.lib ole32.lib shell32.lib bcrypt.lib fwpuclnt.lib iphlpapi.lib ws2_32.lib uuid.lib
set "result=%errorlevel%"
popd
exit /b %result%
