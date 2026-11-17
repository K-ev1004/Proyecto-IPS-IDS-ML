@echo off
setlocal EnableExtensions
title Bateria T v6 (preflight + ejecucion)
rem ============================================================================
rem ejecutar_t_v6.bat - Prepara y ejecuta la batería T*v6 sin contratiempos.
rem
rem NO lanza el sensor, NO registra tareas y NO toca el dataset v6: solo exige
rem que el CSV ya este presente. Ejecuta T1v6..T4v6 (incluye T2v6=T6).
rem T5v6 NO se ejecuta aqui: requiere las 3 CHR encendidas y se lanza aparte.
rem
rem Uso:
rem   scripts\ejecutar_t_v6.bat
rem ============================================================================
cd /d "%~dp0.."

if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    echo [AVISO] No hay .venv; se usara el python del PATH.
    set "PY=python.exe"
)

echo ============================================================================
echo  PREFLIGHT — bateria T*v6
echo ============================================================================

echo.
echo [1] Entorno (dependencias y modelos)
"%PY%" scripts\verificar_entorno.py
if errorlevel 1 (
    echo [X] Entorno incompleto. Corrija antes de ejecutar las T.
    endlocal & exit /b 1
)

echo.
echo [2] Dataset v6 (NO se regenera; debe estar ya en la carpeta)
if not exist "Dataset_Limpio\dataset_global_unipaz_v6.csv" (
    echo [X] Falta Dataset_Limpio\dataset_global_unipaz_v6.csv
    echo     Coloque el CSV v6 ya generado en esa ruta y vuelva a ejecutar.
    echo     Este script NO lo restaura ni lo regenera.
    endlocal & exit /b 1
)
echo [OK] Dataset_Limpio\dataset_global_unipaz_v6.csv presente.

echo.
echo [3] Corpus CSIC 2010 (para T2v6 = T6)
if not exist "datasets\CSIC2010\b1_test-00000-of-00001.parquet" (
    echo [X] Falta datasets\CSIC2010\b1_test-00000-of-00001.parquet
    endlocal & exit /b 1
)
echo [OK] Corpus CSIC presente.

echo.
echo [4] Scripts de la bateria
if not exist "test_masivo_v6.py" (
    echo [X] Falta test_masivo_v6.py
    endlocal & exit /b 1
)
if not exist "docs\lab\t5_routeros_v6.py" (
    echo [X] Falta docs\lab\t5_routeros_v6.py
    endlocal & exit /b 1
)
echo [OK] test_masivo_v6.py y t5_routeros_v6.py presentes.

echo.
echo ============================================================================
echo  EJECUTANDO T1v6 / T2v6 / T3v6 / T4v6
echo ============================================================================
"%PY%" test_masivo_v6.py
set "RC=%errorlevel%"

echo.
echo ============================================================================
echo  T5v6 — NO EJECUTADA
echo ============================================================================
echo  Las 3 CHR estan apagadas/en otro dispositivo. Cuando esten disponibles:
echo    setx MIKROTIK_PROFILE lab
echo    setx IDS_IPS_AUTONOMO 1
echo    "%PY%" docs\lab\t5_routeros_v6.py --evidencia-dir docs\lab\corridas\v6
echo.
echo  Informe: informe_test_masivo_v6.json  ^|  RC=%RC%
echo ============================================================================

endlocal & exit /b %RC%
