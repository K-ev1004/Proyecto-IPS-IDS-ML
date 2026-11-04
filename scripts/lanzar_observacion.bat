@echo off
rem ============================================================================
rem lanzar_observacion.bat - Arranque del IDS v5 en PRODUCCION (24/7)
rem Llamado por la tarea programada "IDS-Observacion-C3" (al iniciar sesion)
rem o a mano.
rem
rem Configuracion 2026-11-04 (calibrada con las 72 h de C3, docs/INFORME_C3_DATOS.md):
rem   - ALERTAS ON (modo produccion), bloqueo OFF: cada evento se notifica por
rem     Telegram y persiste con evidencia; ningun bloqueo sin supervision.
rem   - Umbrales por defecto 50/25/20 validados: en 72 h el trafico normal
rem     nunca los alcanzo (0 alertas heuristicas tras las correcciones).
rem   - ML como instrumentacion unicamente.
rem ============================================================================
cd /d "%~dp0.."

rem Produccion: persiste y ALERTA por Telegram. No bloquea (IPS autonomo off).
set IDS_MODO_OBSERVACION=0
set IDS_IPS_AUTONOMO=0
rem El ML no es via de alerta: solo instrumentacion (corrida C3, 276k FP)
set IDS_ML_ALERTAS=0
if not defined IDS_RUN_ID set IDS_RUN_ID=prod-v5
rem Exencion de exploit decidida 2026-10-28 (TFTP broadcast): hosts de gestion
if not defined IDS_HOSTS_GESTION set IDS_HOSTS_GESTION=172.10.0.57,172.10.0.59
rem 0 = corre 24/7 hasta apagado/cierre de sesion (la tarea lo relanza al login)
if not defined IDS_DURACION_H set IDS_DURACION_H=0
rem Umbrales de escaneo calibrados con C3 (defaults del codigo: 50/25/20).
rem Para afinarlos sin tocar codigo, definir aqui IDS_SCAN_THRESHOLD,
rem IDS_SCAN_THRESHOLD_INT o IDS_SCAN_MIN_DST.
rem Interfaz de captura: "Ethernet" = Realtek 2.5GbE (red UNIPAZ, donde entra
rem el SPAN; IP actual 172.10.12.77 por DHCP). NO usar las VirtualBox (lab CHR).
set IDS_IFACE=Ethernet

if not exist logs_ciberseguridad mkdir logs_ciberseguridad

echo [%date% %time%] Lanzando corrida %IDS_RUN_ID% >> "logs_ciberseguridad\corrida_%IDS_RUN_ID%.log"
"venv\Scripts\python.exe" scripts\corrida_observacion.py >> "logs_ciberseguridad\corrida_%IDS_RUN_ID%.log" 2>&1
