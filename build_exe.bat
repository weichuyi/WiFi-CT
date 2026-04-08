@echo off
chcp 65001 >nul
echo 正在打包 WiFi监控.exe ...

pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo 未检测到 PyInstaller，正在安装...
    pip install pyinstaller
)

pyinstaller WiFi监控.spec --noconfirm

if errorlevel 1 (
    echo.
    echo ❌ 打包失败，请查看上方错误信息
    pause
    exit /b 1
)

echo.
echo ✅ 打包成功！文件在 dist\WiFi监控.exe
explorer dist
pause
