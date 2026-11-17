@echo off
rem ============================================================================
rem lanzar_v6_lab.bat - LABORATORIO (NO produccion): motor v6 activo.
rem
rem Lo llama la tarea programada "IDS-Lab-V6-Activo" al iniciar sesion.
rem NO es produccion: produccion sigue en v5 con IDS-Observacion-C3.
rem
rem Diferencias contra el lanzador de produccion (lanzar_gui.bat):
rem   - IDS_ML_V6=1      -> carga CatBoost v6 + detector de payload
rem   - IDS_ML_SOMBRA=0  -> las 6 clases salen de sombra (M6 activo)
rem   - IDS_RUN_ID=lab-v6-activo -> trazabilidad propia en la BD y en el log
rem
rem IDS_ML_ALERTAS se mantien en 0 a proposito: el v5 sigue en instrumentacion.
rem El canal v6 corre igual (ids.py: on_flow_ready -> canal v6) y las
rem heuristicas v5 siguen alertando. Reactivar el v5 traeria 92.004 FP/dia.
rem
rem Bloqueo OFF (IDS_IPS_AUTONOMO=0): un falso positivo solo molesta; con
rem bloqueo ON cortaria el trafico de un usuario real. No activar sin antes
rem revisar una semana de alertas del run lab-v6-activo.
rem ============================================================================
cd /d "%~dp0.."

set IDS_MODO_OBSERVACION=0
set IDS_IPS_AUTONOMO=0
set IDS_ML_ALERTAS=0
set IDS_ML_V6=1
set IDS_ML_SOMBRA=0
if not defined IDS_RUN_ID set IDS_RUN_ID=lab-v6-activo
set IDS_DURACION_H=0
set IDS_AUTO_INICIAR=1

rem Interfaz: sin fijar, el motor detecta la del laboratorio. Si se necesita
rem forzar, descomentar y poner el nombre de la interfaz SPAN.
rem set IDS_IFACE=Ethernet

rem Intérprete: el proyecto no tiene venv en este checkout. Se usa el Python
rem del sistema (PyQt5 + qfluentwidgets + CatBoost ya instalados) con fallback.
set "PY=C:\Users\rojas\AppData\Local\Programs\Python\Python313\python.exe"
if not exist "%PY%" set "PY=python.exe"

if not exist logs_ciberseguridad mkdir logs_ciberseguridad
echo [%date% %time%] Lanzando GUI laboratorio %IDS_RUN_ID% (v6 activo) >> "logs_ciberseguridad\gui_%IDS_RUN_ID%.log"
"%PY%" interfasc.py >> "logs_ciberseguridad\gui_%IDS_RUN_ID%.log" 2>&1
