@echo off
REM Double-click friendly: forwards to the Python launcher (finds Git bash + runs Docker verify).
REM Need: Docker running, Python 3, bash (install Git for Windows: winget install --id Git.Git -e ).
setlocal
pushd "%~dp0.." || exit /b 2
python "%~dp0agent_linux_verify.py" %*
set EC=%ERRORLEVEL%
popd
exit /b %EC%
