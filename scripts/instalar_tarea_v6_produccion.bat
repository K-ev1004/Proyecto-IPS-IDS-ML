@echo off
rem ============================================================================
rem instalar_tarea_v6_produccion.bat - Arranque automatico de la v6 en ml-v6.
rem
rem *** EJECUTAR COMO ADMINISTRADOR *** (schtasks requiere elevacion; sin ella
rem devuelve "Acceso denegado"). Este .bat SOLO registra la tarea: NO lanza
rem el motor. El lanzamiento ocurre en el PROXIMO inicio de sesion.
rem
rem Disparador ONLOGON: la GUI es el motor y necesita sesion interactiva.
rem No usar ONSTART/SYSTEM. Si la sesion entra sola al encender el PC, equivale
rem a "arrancar al encender".
rem
rem Para desinstalar:
rem   schtasks /delete /tn "IDS-Prod-V6-Activo" /f
rem ============================================================================
set "TAREA=IDS-Prod-V6-Activo"
set "TRAZA=\"%~dp0lanzar_v6_produccion.bat\""

schtasks /create /tn "%TAREA%" /tr "%TRAZA%" /sc ONLOGON /f
if errorlevel 1 (
    echo.
    echo [ERROR] No se pudo registrar la tarea.
    echo Cierra esta ventana y vuelve a abrirla con clic derecho
    echo "Ejecutar como administrador".
) else (
    echo.
    echo [OK] Tarea "%TAREA%" registrada. NO se ha lanzado nada ahora.
    echo Verificando:
    schtasks /query /tn "%TAREA%" /fo LIST /v
)
echo.

rem El instalador completo llama con /NOPAUSE para no cortar su flujo.
if /i not "%~1"=="/NOPAUSE" pause
