@echo off
setlocal EnableExtensions
title Verificacion del entorno - IDS/IPS UNIPAZ

rem ============================================================================
rem verificar_windows.bat - Chequeo de salud en un solo comando.
rem
rem NO lanza el motor, NO abre la GUI, NO inicia la captura.
rem Comprueba: .venv, dependencias Python, modelos (y punteros LFS),
rem servicio Npcap, tarea programada y ultimas lineas del log del run.
rem
rem Uso:
rem   scripts\verificar_windows.bat
rem   call scripts\verificar_windows.bat /NOPAUSE   (para instaladores)
rem ============================================================================

cd /d "%~dp0.."

echo ============================================================================
echo  Verificacion del kit portable - IDS/IPS UNIPAZ (rama ml-v6)
echo ============================================================================
echo Directorio: %CD%

echo.
echo [1] Entorno virtual
if exist ".venv\Scripts\python.exe" (
    echo [OK] .venv\Scripts\python.exe encontrado.
    set "PY=.venv\Scripts\python.exe"
) else (
    echo [AVISO] No hay .venv; se usara el python del PATH.
    echo         Ejecute scripts\instalar_windows.bat como Administrador.
    set "PY=python.exe"
)

echo.
echo [2] Dependencias y modelos
"%PY%" scripts\verificar_entorno.py
set "RC=%errorlevel%"

echo.
echo [3] Driver de captura Npcap
sc query npcap >nul 2>&1
if not errorlevel 1 (
    echo [OK] Servicio npcap detectado.
) else (
    echo [AVISO] No se detecto el servicio npcap.
    echo         Instale Npcap desde https://npcap.com/ como Administrador.
    echo         Este chequeo NO instala drivers.
)

echo.
echo [4] Arranque automatico
schtasks /query /tn "IDS-Lab-V6-Activo" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Tarea "IDS-Lab-V6-Activo" registrada.
) else (
    echo [AVISO] Tarea "IDS-Lab-V6-Activo" NO registrada.
    echo         Ejecute scripts\instalar_windows.bat como Administrador.
)

echo.
echo [5] Log del run activo
if exist "logs_ciberseguridad\gui_lab-v6-activo.log" (
    echo [OK] Log presente. Ultimas 5 lineas:
    powershell -NoProfile -Command "Get-Content -LiteralPath 'logs_ciberseguridad\gui_lab-v6-activo.log' -Tail 5"
) else (
    echo [INFO] Todavia no hay log del run. Es normal si aun no ha iniciado
    echo         sesion desde la instalacion: el lanzador no se ejecuto ahora.
)

echo.
echo ============================================================================
if "%RC%"=="0" (
    echo  RESULTADO: entorno correcto. Los avisos de Npcap/tarea son informativos.
) else (
    echo  RESULTADO: hay problemas en dependencias o modelos.
)
echo ============================================================================

if /i not "%~1"=="/NOPAUSE" pause
endlocal & exit /b %RC%
