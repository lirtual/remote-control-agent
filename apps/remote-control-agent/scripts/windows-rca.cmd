@echo off
setlocal DisableDelayedExpansion
"%~dp0bin\node.exe" "%~dp0apps\remote-control-agent\src\windows-v2.js" %*
exit /b %ERRORLEVEL%
