@echo off
rem ============================================================================
rem lanzar_observacion.bat - Arranque del IDS v5 en modo observacion (fase C3)
rem Llamado por la tarea programada "IDS-Observacion-C3" o a mano.
rem ============================================================================
cd /d "%~dp0.."

set IDS_MODO_OBSERVACION=1
rem Umbrales/ventanas: usar los defectos del codigo salvo que se definan antes
if not defined IDS_RUN_ID set IDS_RUN_ID=obs-c3-20261028
rem Exencion de exploit decidida 2026-10-28 (TFTP broadcast): hosts de gestion
if not defined IDS_HOSTS_GESTION set IDS_HOSTS_GESTION=172.10.0.57,172.10.0.59
rem Duracion: 0 = hasta detener manualmente (schtasks /End o Ctrl+C)
if not defined IDS_DURACION_H set IDS_DURACION_H=0
rem IDS_IFACE: fijar con el nombre de la interfaz donde entra el SPAN, p. ej.:
rem set IDS_IFACE=Ethernet

if not exist logs_ciberseguridad mkdir logs_ciberseguridad

echo [%date% %time%] Lanzando corrida %IDS_RUN_ID% >> "logs_ciberseguridad\corrida_%IDS_RUN_ID%.log"
"venv\Scripts\python.exe" scripts\corrida_observacion.py >> "logs_ciberseguridad\corrida_%IDS_RUN_ID%.log" 2>&1
