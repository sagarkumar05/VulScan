@echo off
:: =============================================================================
:: run_scanner.bat — Windows One-Click Runner
:: =============================================================================
:: Double-click this file to run VulnScanner on Windows
:: UPDATE: Python path change karna hai to line 15 modify karo
:: =============================================================================

title VulnScanner - Web Vulnerability Scanner

echo.
echo  =====================================================
echo    VulnScanner - B.Tech Final Year Project
echo  =====================================================
echo.

:: Check if Python is installed
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] Python not found! Please install Python 3.8+ from python.org
    echo  Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

:: Go to the script directory (wherever the bat file is)
cd /d "%~dp0"

:: Check if VulnScanner folder exists
if not exist "VulnScanner\main.py" (
    echo  [ERROR] VulnScanner\main.py not found!
    echo  Make sure run_scanner.bat is in the same folder as VulnScanner\
    pause
    exit /b 1
)

:: Install requirements if not done
echo  [*] Installing/checking requirements...
pip install -r VulnScanner\requirements.txt --quiet
if %ERRORLEVEL% NEQ 0 (
    echo  [WARNING] Some packages may not have installed. Trying to continue...
)

:: Run the scanner
echo.
echo  [*] Starting VulnScanner...
echo.
cd VulnScanner
python main.py %*

echo.
echo  [*] Scanner finished. Check reports\ folder for results.
pause
