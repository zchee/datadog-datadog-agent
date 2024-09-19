REM don't let variables escape
@echo off
@setlocal

REM as defined in the usage block, expected parameters are
REM %1 is the root of the build filesystem, which determines the location of the tar.gz
REM %2 is the base name (without extension) of the file to be expanded.  expected values right now
REM    are `modcache` and `modcache_tools`

if "%1" == "" (
    goto :usage
)
if "%2" == "" (
    goto :usage
)

set MODCACHE_ROOT=%1
set MODCACHE_FILE_ROOT=%2
set MODCACHE_ZIP_FILE=%MODCACHE_ROOT%\%MODCACHE_FILE_ROOT%.zip

if "%GOMODCACHE%" == "" (
    @echo GOMODCACHE environment variable not set, skipping expansion of mod cache files
    goto :endofscript
)

@echo MODCACHE_ZIP_FILE %MODCACHE_ZIP_FILE% GOMODCACHE %GOMODCACHE%
if exist %MODCACHE_ZIP_FILE% (
    @echo Extracting modcache file %MODCACHE_ZIP_FILE%
    REM Use -aoa to allow overwriting existing files
    REM This shouldn't have any negative impact: since modules are
    REM stored per version and hash, files that get replaced will
    REM get replaced by the same files
    Powershell -C "7z x %MODCACHE_ZIP_FILE% -o%GOMODCACHE% -aoa -bt"
    @echo Modcache extracted
) else (
    @echo %MODCACHE_ZIP_FILE% not found, dependencies will be downloaded
)
goto :endofscript

:usage
@echo usage
@echo "extract-modcache <build root> <filename>"
goto :eof

:endofscript
if exist %MODCACHE_ZIP_FILE% (
    @echo deleting modcache zip %MODCACHE_ZIP_FILE%
    del /f %MODCACHE_ZIP_FILE%
)
goto :EOF



@endlocal
