@echo off
rem ============================================================================
rem grabber_http_benigno.bat - Captura del corpus HTTP benigno UNIPAZ (ML v6 M2).
rem
rem La tarea programada (al iniciar sesion) llama ESTE archivo: si el servidor
rem se apaga, la captura se relanza sola al volver la sesion. La BD es
rem datasets\unipaz_http\captura_http_benigno.db y el conteo acumulado vive en
rem la propia BD, asi que un apagon no pierde la corrida ni reinicia el conteo.
rem
rem Instalacion de la tarea (una sola vez, como usuario):
rem   schtasks /create /tn "Grabber-HTTP-v6" /tr "%~f0" /sc onlogon /f
rem Desinstalar:
rem   schtasks /delete /tn "Grabber-HTTP-v6" /f
rem Ver estado: schtasks /query /tn "Grabber-HTTP-v6"
rem ============================================================================
cd /d "%~dp0.."

rem Misma interfaz que produccion: "Ethernet" = Realtek 2.5GbE (SPAN).
if not defined IDS_IFACE set IDS_IFACE=Ethernet

if not exist logs_ciberseguridad mkdir logs_ciberseguridad

echo [%date% %time%] Grabber HTTP v6 arrancando (iface=%IDS_IFACE%) >> "logs_ciberseguridad\grabber_http.log"
"venv\Scripts\python.exe" scripts\grabber_http_benigno.py >> "logs_ciberseguridad\grabber_http.log" 2>&1
