@echo off
rem ============================================================================
rem lanzar_gui.bat - Produccion 24/7 con la GUI visible (interfasc.py).
rem
rem La GUI ES el motor: al abrirse muestra dashboard, eventos y mapa, y con
rem IDS_AUTO_INICIAR=1 arranca la captura sola (sin clicks). La ventana NO debe
rem cerrarse (cerrarla detiene la captura; minimizar no afecta).
rem
rem Configuracion calibrada con las 72 h de C3 (docs/INFORME_C3_DATOS.md):
rem   - ALERTAS ON (observacion off), bloqueo OFF.
rem   - Umbrales por defecto 50/25/20: el trafico normal nunca los alcanzo.
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
rem La GUI corre mientras haya sesion; la tarea la relanza al iniciar sesion.
set IDS_DURACION_H=0
rem Auto-arranque de la captura al abrir la ventana (sin clicks)
set IDS_AUTO_INICIAR=1
rem Umbrales de escaneo calibrados con C3 (defaults del codigo: 50/25/20).
rem Para afinarlos sin tocar codigo, definir aqui IDS_SCAN_THRESHOLD,
rem IDS_SCAN_THRESHOLD_INT o IDS_SCAN_MIN_DST.
rem Interfaz de captura: "Ethernet" = Realtek 2.5GbE (red UNIPAZ, donde entra
rem el SPAN; IP actual 172.10.12.77 por DHCP). NO usar las VirtualBox (lab CHR).
set IDS_IFACE=Ethernet

if not exist logs_ciberseguridad mkdir logs_ciberseguridad

echo [%date% %time%] Lanzando GUI de produccion %IDS_RUN_ID% >> "logs_ciberseguridad\gui_%IDS_RUN_ID%.log"
rem El stdout/stderr del motor queda en el log; la ventana de la GUI se abre
rem igual porque es una ventana Qt, no de consola.
"venv\Scripts\python.exe" interfasc.py >> "logs_ciberseguridad\gui_%IDS_RUN_ID%.log" 2>&1
