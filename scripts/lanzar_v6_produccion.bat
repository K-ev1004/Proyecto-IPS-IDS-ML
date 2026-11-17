@echo off
rem ============================================================================
rem lanzar_v6_produccion.bat - PRODUCCION v6 dentro de la rama ml-v6.
rem
rem Este lanzador deja el proyecto funcional con el ML v6 activo. No mergea a
rem main: main se conserva como linea base v5. Utiliza rutas relativas y el
rem .venv local creado por scripts\instalar_windows.bat.
rem
rem Flags efectivos (los de este lanzador mandan sobre .env):
rem   IDS_ML_V6=1            -> CatBoost v6 + detector de payload
rem   IDS_ML_SOMBRA=0        -> clases activas (politica M4/M6)
rem   IDS_ML_ALERTAS=0       -> v5 sigue en instrumentacion; el canal v6 corre
rem   IDS_IPS_AUTONOMO=0     -> NO bloquea en MikroTik (solo alerta/persiste)
rem   IDS_MODO_OBSERVACION=0 -> permite la respuesta de alerta de la v6
rem   IDS_RUN_ID=prod-v6-activo -> trazabilidad propia en BD y logs
rem
rem Rollback rapido sin tocar codigo:
rem   - IDS_POLITICA=sombra     -> nada notifica
rem   - IDS_POLITICA=heuristica -> produccion v5 exacta
rem   - cerrar y usar scripts\lanzar_gui.bat desde main
rem ============================================================================
cd /d "%~dp0.."

rem Configuracion local (.env): se lee primero; los flags de abajo tienen
rem prioridad. Formato CLAVE=VALOR, sin comillas, # para comentarios.
if exist "%~dp0..\.env" (
    for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%~dp0..\.env") do (
        set "%%A=%%B"
    )
)

set IDS_MODO_OBSERVACION=0
set IDS_IPS_AUTONOMO=0
set IDS_ML_ALERTAS=0
set IDS_ML_V6=1
set IDS_ML_SOMBRA=0
set IDS_RUN_ID=prod-v6-activo
set IDS_DURACION_H=0
set IDS_AUTO_INICIAR=1

rem Interfaz: vacio = deteccion automatica. Forzar solo si hace falta:
rem set IDS_IFACE=Ethernet

set "PY=%~dp0..\.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python.exe"

if not exist logs_ciberseguridad mkdir logs_ciberseguridad
echo [%date% %time%] Lanzando GUI PRODUCCION %IDS_RUN_ID% (v6 activo) >> "logs_ciberseguridad\gui_%IDS_RUN_ID%.log"
"%PY%" interfasc.py >> "logs_ciberseguridad\gui_%IDS_RUN_ID%.log" 2>&1
