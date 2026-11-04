@echo off
rem ============================================================================
rem lanzar_observacion.bat - Punto de entrada unico de produccion.
rem La tarea programada "IDS-Observacion-C3" (al iniciar sesion) llama ESTE
rem archivo, asi que aqui se decide QUE corre en produccion.
rem
rem Desde 2026-11-04 la produccion corre con la GUI visible (interfasc.py):
rem la ventana muestra dashboard/eventos/mapa y arranca la captura sola
rem (IDS_AUTO_INICIAR=1). Toda la configuracion vive en lanzar_gui.bat.
rem
rem Alternativa headless (servidor sin sesion interactiva): usar
rem scripts\corrida_observacion.py con las mismas variables de entorno
rem (ver docs/LANZAMIENTO_PRODUCCION.md).
rem ============================================================================
call "%~dp0lanzar_gui.bat"
