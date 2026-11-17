@echo off
setlocal EnableExtensions
title Actualizacion del kit portable - IDS/IPS UNIPAZ

rem ============================================================================
rem actualizar_windows.bat - Trae una version nueva del proyecto sin
rem reinstalar desde cero: git pull + git lfs pull + pip en el .venv existente.
rem
rem Si la carpeta se copio SIN repo git, omite el pull y solo actualiza
rem dependencias; en ese caso reemplace la carpeta por la version nueva.
rem NO lanza el motor.
rem ============================================================================

cd /d "%~dp0.."
echo ============================================================================
echo  Actualizacion del kit portable - IDS/IPS UNIPAZ
echo ============================================================================
echo Directorio: %CD%

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] No existe .venv. Ejecute primero scripts\instalar_windows.bat
    pause
    exit /b 1
)
set "PY=.venv\Scripts\python.exe"

echo.
echo [1/3] Actualizando codigo y modelos...
if exist ".git" (
    git pull
    if errorlevel 1 goto :fallo
    git lfs install --local
    git lfs pull
    if errorlevel 1 (
        echo [AVISO] git lfs pull fallo; el verificador revisara los .pkl.
    ) else (
        echo [OK] Codigo y modelos actualizados.
    )
) else (
    echo [AVISO] Esta carpeta no es un clon git; no hay 'git pull'.
    echo         Copie la version nueva encima y vuelva a verificar.
)

echo.
echo [2/3] Actualizando dependencias...
"%PY%" -m pip install -r requirements-windows.txt
if errorlevel 1 goto :fallo
echo [OK] Dependencias al dia.

echo.
echo [3/3] Verificando...
call "%~dp0verificar_windows.bat" /NOPAUSE

echo.
echo [OK] Actualizacion terminada. El motor NO se ha lanzado.
echo      Si la tarea esta activa, se iniciara en el proximo inicio de sesion.
pause
exit /b 0

:fallo
echo.
echo [ERROR] Fallo la actualizacion. Revise el mensaje anterior.
pause
exit /b 1
