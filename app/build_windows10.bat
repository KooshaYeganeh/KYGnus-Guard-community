@echo off
cls
echo ==========================================
echo [*] Building Hermes Executable for Windows 10
echo ==========================================
timeout /t 1 >nul

:: Step 1: Build the executable
echo.
echo [1] Creating the executable...
pyinstaller main_linux.py --onefile --add-data "templates;templates" --add-data "static;static" -n hermes_mswindows_10.exe

:: Check if the build was successful
if not exist "dist\hermes_mswindows_10.exe" (
    echo.
    echo [ERROR] Build failed! Please check for errors.
    pause
    exit /b 1
)

:: Step 2: Copy the EXE to current directory
echo.
echo [2] Copying the EXE to current directory...
copy "dist\hermes_mswindows_10.exe" ".\" >nul

:: Step 3: Clean up build files
echo.
echo [3] Cleaning up temporary build files...
rmdir /s /q dist
rmdir /s /q build
del /q hermes_mswindows_10.exe.spec

:: Done
echo.
echo [✓] Build complete!
echo [✔] Executable: hermes_mswindows_10.exe
echo [📌] Location: %cd%
echo ==========================================
echo [🎉] You can now run the executable.
echo ==========================================
pause
