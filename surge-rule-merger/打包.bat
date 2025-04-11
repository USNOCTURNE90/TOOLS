@echo off
chcp 65001 > nul
title 打包Surge规则合并工具
echo 准备打包Surge规则合并工具...
echo.

REM 检查必要文件是否存在
echo 检查必要文件...
set MISSING=0
if not exist "index.html" (
    echo [错误] 未找到 index.html 文件
    set MISSING=1
)
if not exist "script.js" (
    echo [错误] 未找到 script.js 文件
    set MISSING=1
)
if not exist "styles.css" (
    echo [错误] 未找到 styles.css 文件
    set MISSING=1
)
if not exist "启动Surge规则合并工具.bat" (
    echo [错误] 未找到 启动Surge规则合并工具.bat 文件
    set MISSING=1
)
if not exist "README.md" (
    echo [警告] 未找到 README.md 文件
)

if "%MISSING%"=="1" (
    echo.
    echo 发现缺失文件，打包中止！请确保所有必要文件都存在。
    pause
    exit /b
)

echo 所有必要文件已找到!
echo.

REM 创建打包目录
set PACKAGE_DIR=Surge规则合并工具_发布包
echo 创建打包目录: %PACKAGE_DIR%...
if exist "%PACKAGE_DIR%" (
    rmdir /s /q "%PACKAGE_DIR%"
)
mkdir "%PACKAGE_DIR%"

REM 复制文件到打包目录
echo 正在复制文件...
copy "index.html" "%PACKAGE_DIR%\" > nul
copy "script.js" "%PACKAGE_DIR%\" > nul
copy "styles.css" "%PACKAGE_DIR%\" > nul
copy "启动Surge规则合并工具.bat" "%PACKAGE_DIR%\" > nul
copy "README.md" "%PACKAGE_DIR%\" > nul
copy "package.json" "%PACKAGE_DIR%\" > nul
copy "打包说明.txt" "%PACKAGE_DIR%\" > nul
echo 已复制基本文件

REM 复制所有脚本和样式文件
echo 正在复制额外脚本和样式文件...
for %%f in (script*.js) do (
    if not "%%f"=="script.js" (
        echo 复制: %%f
        copy "%%f" "%PACKAGE_DIR%\" > nul
    )
)
for %%f in (style*.css) do (
    if not "%%f"=="styles.css" (
        echo 复制: %%f
        copy "%%f" "%PACKAGE_DIR%\" > nul
    )
)

REM 检查打包结果
echo.
echo 检查打包结果...
dir "%PACKAGE_DIR%"

echo.
echo 打包完成!
echo 打包目录: %PACKAGE_DIR%

REM 提示用户可以创建ZIP文件
echo.
echo 接下来可以右键点击 %PACKAGE_DIR% 文件夹，选择"发送到" > "压缩(zipped)文件夹"
echo 创建可分发的ZIP文件。
echo.
pause 