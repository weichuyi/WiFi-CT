@echo off
chcp 65001 >nul
echo 正在检查Python环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到Python，请先安装Python 3.8+
    pause
    exit /b
)

echo 正在安装依赖...
pip install scapy psutil -q

echo 启动WiFi热点流量监控（需要管理员权限）...
python "%~dp0wifi_monitor.py"
pause
