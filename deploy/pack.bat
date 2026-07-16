@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set APP_NAME=LicenseManager
set OUTPUT_DIR=%SCRIPT_DIR%output
set GMSSL_LIB_DIR=%PROJECT_DIR%\gmssl\win\lib
set BUILD_DIR=%PROJECT_DIR%\build_release
set RELEASE_DIR=%PROJECT_DIR%\release

rem Parse -m flag (compile only, skip packaging)
set BUILD_ONLY=0
if /i "%1"=="-m" set BUILD_ONLY=1

echo ==============================================
echo  LicenseManager Windows x86_64 Build Script
echo ==============================================
if %BUILD_ONLY%==1 echo  Mode: Compile only (-m)
echo ==============================================

rem ==== 1. Check dependencies ====
echo.
echo [1/4] Checking environment...

where qmake.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: qmake.exe not found. Make sure you are running in Qt 5.15.2 MinGW terminal.
    exit /b 1
)
echo   qmake: OK

where mingw32-make.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: mingw32-make.exe not found.
    exit /b 1
)
echo   mingw32-make: OK

if %BUILD_ONLY%==0 (
    where windeployqt.exe >nul 2>&1
    if %errorlevel% neq 0 (
        echo Error: windeployqt.exe not found.
        exit /b 1
    )
    echo   windeployqt: OK
)

rem ==== 2. Build Release (out-of-source) ====
echo.
echo [2/4] Building Release...

rem Clean build directory
if exist "%BUILD_DIR%" (
    echo   Cleaning build directory...
    rmdir /s /q "%BUILD_DIR%" >nul 2>&1
)
mkdir "%BUILD_DIR%" >nul 2>&1

cd /d "%BUILD_DIR%"

qmake "%PROJECT_DIR%\licensemanager.pro" CONFIG+=release
if %errorlevel% neq 0 (
    echo Error: qmake failed.
    cd /d "%PROJECT_DIR%"
    exit /b 1
)

mingw32-make -j4
if %errorlevel% neq 0 (
    echo Error: make failed.
    cd /d "%PROJECT_DIR%"
    exit /b 1
)

cd /d "%PROJECT_DIR%"

rem .pro file sets DESTDIR = $$PWD/release, so exe goes to project's release\
rem Ensure the output directory exists (make may or may not create it)
if not exist "%RELEASE_DIR%" mkdir "%RELEASE_DIR%"

set APP_BIN=%RELEASE_DIR%\%APP_NAME%.exe
if not exist "%APP_BIN%" (
    echo Error: Build output not found: %APP_BIN%
    exit /b 1
)
echo   Output: %APP_BIN%

rem If -m flag, stop here
if %BUILD_ONLY%==1 (
    echo.
    echo ==============================================
    echo  Build-only complete
    echo  Binary: %APP_BIN%
    echo ==============================================
    endlocal
    exit /b 0
)

rem ==== 3. windeployqt ====
echo.
echo [3/4] Running windeployqt...

pushd "%RELEASE_DIR%"
windeployqt "%APP_NAME%.exe" --no-translations --no-system-d3d-compiler --no-opengl-sw
if %errorlevel% neq 0 (
    echo Warning: windeployqt reported errors, deploy may be incomplete.
)
popd

rem ==== 4. Copy GmSSL DLL ====
echo.
echo [3/4] Copying GmSSL runtime...

set GMSSL_DLL=%GMSSL_LIB_DIR%\libgmssl.dll
if exist "%GMSSL_DLL%" (
    copy /y "%GMSSL_DLL%" "%RELEASE_DIR%"
    echo   libgmssl.dll copied
) else (
    echo Warning: libgmssl.dll not found at %GMSSL_DLL%
)

rem ==== 5. Create zip ====
echo.
echo [4/4] Packaging output...

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set ZIP_NAME=%APP_NAME%-win64.zip
set ZIP_PATH=%OUTPUT_DIR%\%ZIP_NAME%
if exist "%ZIP_PATH%" del "%ZIP_PATH%"

echo   Files to package:
dir "%RELEASE_DIR%" /b /a-d /w

rem Use PowerShell for zip creation
powershell -NoProfile -Command "Compress-Archive -Path '%RELEASE_DIR%\*' -DestinationPath '%ZIP_PATH%' -Force"
if %errorlevel% neq 0 (
    echo Error: Failed to create zip archive.
    exit /b 1
)

echo.
echo ==============================================
echo  Build complete
echo  Output: %ZIP_PATH%
echo ==============================================

endlocal
