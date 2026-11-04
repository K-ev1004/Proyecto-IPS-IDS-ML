@echo off
rem ============================================================================
rem lanzar_gui_v6.bat - FASE SOMBRA M5 del ML v6 (laboratorio, rama ml-v6).
rem
rem La tarea programada "IDS-Lab-M5-V6" (al iniciar sesion) llama ESTE archivo:
rem si el servidor se apaga, al volver la sesion la GUI se abre sola y la
rem captura CONTINUA. Nada se pierde: la BD (intrusiones_v5.db del laboratorio)
rem guarda cada ataque y cada ml_candidato con commit inmediato, y el run_id
rem por arranque permite comparar ventanas.
rem
rem Diferencias con produccion (lanzar_gui.bat, carpeta main — INTACTA):
rem   IDS_ML_V6=1        carga CatBoost v6 + detector payload + umbral por clase
rem   IDS_ML_SOMBRA=1    TODO candidato va a ml_candidatos; NADA notifica/bloquea
rem   IDS_RUN_ID=lab-m5-shadow   sello de la fase sombra (M5)
rem   Alertas heuristicas ON (para comparar ML vs heuristica dia a dia),
rem   bloqueo OFF (nunca bloquea el laboratorio).
rem
rem Detener la fase: cerrar la ventana GUI o: schtasks /end /tn "IDS-Lab-M5-V6"
rem Ver progreso diario: ver ML_V6_DESARROLLO.md §3.1 / consulta ml_candidatos.
rem ============================================================================
cd /d "%~dp0.."

rem Interfaz de captura: la misma de produccion (SPAN en Realtek 2.5GbE)
if not defined IDS_IFACE set IDS_IFACE=Ethernet

rem --- MODO SOMBRA M5 ---------------------------------------------------------
set IDS_ML_V6=1
set IDS_ML_SOMBRA=1
rem Matriz default (conservadora); en M6 se endurece por clase via el JSON
if not defined IDS_POLITICA set IDS_POLITICA=
rem Heuristicas alertan (nivel 1, como produccion); ML v6 solo graba candidatos
set IDS_MODO_OBSERVACION=0
set IDS_IPS_AUTONOMO=0
set IDS_ML_ALERTAS=0
rem Sello de la fase sombra
set IDS_RUN_ID=lab-m5-shadow
rem Correr hasta apagado (el task la relanza al iniciar sesion)
set IDS_DURACION_H=0
rem La GUI abre la captura sola (sin clicks) — igual que produccion
set IDS_AUTO_INICIAR=1

if not exist logs_ciberseguridad mkdir logs_ciberseguridad

echo [%date% %time%] Lanzando GUI laboratorio v6 (M5 sombra, iface=%IDS_IFACE%) >> "logs_ciberseguridad\gui_v6_m5.log"
"venv\Scripts\python.exe" interfasc.py >> "logs_ciberseguridad\gui_v6_m5.log" 2>&1
