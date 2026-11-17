@echo off
rem ============================================================================
rem instalar_tarea_v6_lab.bat - Registra el arranque automatico del v6 de LAB.
rem
rem *** EJECUTAR COMO ADMINISTRADOR *** (schtasks requiere elevacion; sin ella
rem devuelve "Acceso denegado"). Este .bat SOLO registra la tarea: NO lanza
rem el motor. El lanzamiento ocurrira en el PROXIMO inicio de sesion.
rem
rem Disparador ONLOGON (al iniciar sesion), igual que el resto del proyecto.
rem No usar ONSTART/SYSTEM: la GUI es el motor y necesita sesion interactiva.
rem Si la sesion inicia sola al encender el PC (netplwiz), equivale a
rem "arrancar al encender".
rem
rem Para desinstalar:
rem   schtasks /delete /tn "IDS-Lab-V6-Activo" /f
rem ============================================================================
set "TAREA=IDS-Lab-V6-Activo"
set "TRAZA=\"%~dp0lanzar_v6_lab.bat\""

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
pause
