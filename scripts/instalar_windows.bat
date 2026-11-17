@echo off
setlocal EnableExtensions
title Instalador portable de Windows - IDS/IPS UNIPAZ

rem ============================================================================
rem instalar_windows.bat - Instalador de UN CLIC para el kit portable Windows.
rem
rem *** EJECUTAR COMO ADMINISTRADOR *** (necesario para registrar la tarea).
rem
rem Hace: crear .venv, instalar dependencias pinnadas, bajar modelos con Git
rem LFS (si hay repo), detectar Npcap (SOLO avisar), crear carpetas, copiar
rem .env.example a .env, registrar la tarea IDS-Lab-V6-Activo y verificar.
rem
rem NO lanza el motor. El arranque ocurre en el PROXIMO inicio de sesion.
rem NO instala Npcap automaticamente (es un driver y requiere licencia OEM
rem para redistribuirlo). Tampoco requiere Docker ni Python embebido.
rem ============================================================================

echo ============================================================================
echo  Instalador portable de Windows - IDS/IPS UNIPAZ (rama ml-v6)
echo ============================================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Este instalador DEBE ejecutarse como Administrador.
    echo   Clic derecho en el archivo -^> Ejecutar como administrador.
    echo   Motivo: schtasks requiere elevacion; sin ella da "Acceso denegado".
    pause
    exit /b 1
)
echo [OK] Permisos de Administrador confirmados.

cd /d "%~dp0.."
if not exist "%CD%\ids.py" (
    echo [ERROR] No encuentro ids.py en %CD%
    echo   Coloque este .bat dentro de la carpeta scripts\ del proyecto.
    pause
    exit /b 1
)
echo [OK] Proyecto detectado en: %CD%

echo.
echo [1/7] Buscando Python...
set "PYCMD="
where py >nul 2>&1
if not errorlevel 1 (
    py -3.12 -c "import sys" >nul 2>&1
    if not errorlevel 1 (
        set "PYCMD=py -3.12"
    ) else (
        py -3 -c "import sys" >nul 2>&1
        if not errorlevel 1 set "PYCMD=py -3"
    )
)
if not defined PYCMD (
    where python >nul 2>&1
    if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD goto :sin_python
echo [OK] Se usara: %PYCMD%

echo.
echo [2/7] Creando entorno virtual .venv...
if exist ".venv\Scripts\python.exe" (
    echo [OK] Ya existe .venv; se reutiliza. Instalacion idempotente.
) else (
    %PYCMD% -m venv .venv
    if errorlevel 1 goto :fallo
    echo [OK] .venv creado.
)
set "PY=.venv\Scripts\python.exe"

echo.
echo [3/7] Instalando dependencias pinnadas...
"%PY%" -m pip install --upgrade pip
if errorlevel 1 goto :fallo
"%PY%" -m pip install -r requirements-windows.txt
if errorlevel 1 goto :fallo
echo [OK] Dependencias instaladas en .venv.

echo.
echo [4/7] Modelos (Git LFS)...
if exist ".git" (
    where git >nul 2>&1
    if not errorlevel 1 (
        git lfs install --local
        git lfs pull
        if errorlevel 1 (
            echo [AVISO] git lfs pull fallo. El verificador revisara los .pkl.
        ) else (
            echo [OK] Modelos descargados con Git LFS.
        )
    ) else (
        echo [AVISO] Git no esta en PATH; no se puede hacer git lfs pull.
    )
) else (
    echo [INFO] Esta carpeta no es un clon git: se usan los .pkl incluidos.
    echo        El verificador comprobara que no sean punteros LFS.
)

echo.
echo [5/7] Comprobando Npcap (no se instala automaticamente)...
sc query npcap >nul 2>&1
if not errorlevel 1 (
    echo [OK] Servicio npcap detectado.
) else (
    echo [AVISO] Npcap NO detectado.
    echo   Instale Npcap desde https://npcap.com/ como Administrador
    echo   y reinice antes de arrancar el sensor. La deteccion sin driver
    echo   no captura trafico real.
)

echo.
echo [6/7] Preparando carpetas y configuracion...
if not exist logs_ciberseguridad mkdir logs_ciberseguridad
if not exist backups mkdir backups
if not exist .env (
    copy /y .env.example .env >nul
    echo [OK] .env creado desde .env.example, sin secretos reales.
) else (
    echo [OK] .env ya existe; no se sobrescribe.
)

echo.
echo [7/7] Registrando arranque automatico (IDS-Lab-V6-Activo)...
call "%~dp0instalar_tarea_v6_lab.bat" /NOPAUSE

echo.
echo Verificando el entorno instalado...
call "%~dp0verificar_windows.bat" /NOPAUSE

echo.
echo ============================================================================
echo  INSTALACION TERMINADA
echo  - .venv con dependencias pinnadas
echo  - modelos v5 + v6 verificados
echo  - tarea IDS-Lab-V6-Activo registrada (ONLOGON)
echo  - el motor NO se ha lanzado
echo.
echo  Proximos pasos:
echo   1. Si aparecio el aviso de Npcap, instalarlo desde https://npcap.com/
echo   2. Cerrar sesion y volver a iniciarla
echo   3. Revisar: logs_ciberseguridad\gui_lab-v6-activo.log
echo      Debe aparecer "[OK] Modelos v6 cargados (sombra=NO)"
echo ============================================================================
pause
exit /b 0

:sin_python
echo.
echo [ERROR] No se encontro Python.
echo   Instale Python 3.12 de 64 bits desde https://www.python.org/downloads/
echo   marque "Add Python to PATH" y vuelva a ejecutar este instalador.
pause
exit /b 1

:fallo
echo.
echo [ERROR] Fallo durante la instalacion. Revise el mensaje anterior.
echo   Si fallo pip, compruebe conexion a internet y vuelva a ejecutar.
pause
exit /b 1
