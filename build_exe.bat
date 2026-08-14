@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

python -m pip install -q -r requirements.txt
if errorlevel 1 exit /b 1

python -m PyInstaller --noconfirm --clean --distpath release_clean --workpath build_clean build_exe.spec
if errorlevel 1 exit /b 1

echo Built: release_clean\工单生成工具.exe
endlocal
