@echo off
chcp 65001 > nul
title Surge规则合并工具
echo 正在启动Surge规则合并工具...
echo.

REM 检查是否存在Microsoft Edge浏览器
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" --app="%~dp0index.html" --window-size=1000,800
    goto :end
)

REM 如果没有Edge，尝试Chrome
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" --app="%~dp0index.html" --window-size=1000,800
    goto :end
)

REM 如果没有Chrome，尝试Firefox
if exist "%ProgramFiles%\Mozilla Firefox\firefox.exe" (
    start "" "%ProgramFiles%\Mozilla Firefox\firefox.exe" -new-window "%~dp0index.html"
    goto :end
)

REM 如果所有浏览器都不存在，使用默认浏览器打开
start "" "%~dp0index.html"

:end
exit 