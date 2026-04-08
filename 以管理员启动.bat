@echo off
chcp 65001 >nul
:: 以管理员身份重新启动
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在请求管理员权限...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo 正在安装依赖...
pip install scapy psutil -q

echo 启动WiFi热点流量监控（管理员模式）...
python "%~dp0wifi_monitor.py"
pause
