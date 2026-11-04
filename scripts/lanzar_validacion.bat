@echo off
rem ============================================================================
rem lanzar_validacion.bat - Validacion instrumentada de la via heuristica (24 h)
rem No es la corrida de produccion: sirve para confirmar que con ML apagado
rem no hay falsos positivos y que nmap/SQLi/floods siguen detectandose.
rem ============================================================================
cd /d "%~dp0.."

set IDS_MODO_OBSERVACION=1
set IDS_ML_ALERTAS=0
set IDS_RUN_ID=val-v5-heuristica
set IDS_HOSTS_GESTION=172.10.0.57,172.10.0.59
rem 12 h por defecto; se puede sobreescribir antes de lanzar.
if not defined IDS_DURACION_H set IDS_DURACION_H=12
set IDS_IFACE=Ethernet

if not exist logs_ciberseguridad mkdir logs_ciberseguridad

echo [%date% %time%] Lanzando VALIDACION %IDS_RUN_ID% (%IDS_DURACION_H% h) >> "logs_ciberseguridad\validacion_%IDS_RUN_ID%.log"
"venv\Scripts\python.exe" scripts\corrida_observacion.py >> "logs_ciberseguridad\validacion_%IDS_RUN_ID%.log" 2>&1
