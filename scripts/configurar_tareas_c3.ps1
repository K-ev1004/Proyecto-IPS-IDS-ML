# ============================================================================
# configurar_tareas_c3.ps1 - Prepara el servidor para la fase C3 (72 h).
# EJECUTAR COMO ADMINISTRADOR:
#     powershell -ExecutionPolicy Bypass -File scripts\configurar_tareas_c3.ps1
# Crea dos tareas programadas y aplica los ajustes de energía.
# ============================================================================

$raiz = Split-Path -Parent $PSScriptRoot

Write-Host "[1/3] Evitando que el servidor se duerma..."
powercfg /change standby-timeout-ac 0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null

Write-Host "[2/3] Tarea 'IDS-Observacion-C3' (al arrancar, reinicia si falla)..."
$accion = New-ScheduledTaskAction -Execute "$raiz\scripts\lanzar_observacion.bat" `
    -WorkingDirectory $raiz
$disparador = New-ScheduledTaskTrigger -AtStartup
# ExecutionTimeLimit de 7 dias: el limite por defecto (72 h) mataria la corrida
# justo al terminar. Reinicio: 3 intentos cada 1 min.
$ajustes = New-ScheduledTaskSettingsSet -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Days 7)
Register-ScheduledTask -TaskName "IDS-Observacion-C3" -Action $accion `
    -Trigger $disparador -Settings $ajustes -User "SYSTEM" -RunLevel Highest -Force | Out-Null

Write-Host "[3/3] Tarea 'IDS-Backup' (diaria 06:00, con purga >90 dias)..."
$accionBk = New-ScheduledTaskAction -Execute "$raiz\venv\Scripts\python.exe" `
    -Argument "scripts\backup_bd.py" -WorkingDirectory $raiz
$disparadorBk = New-ScheduledTaskTrigger -Daily -At 06:00
Register-ScheduledTask -TaskName "IDS-Backup" -Action $accionBk `
    -Trigger $disparadorBk -User "SYSTEM" -RunLevel Highest -Force | Out-Null

Write-Host ""
Write-Host "[OK] Listo. Verificar:  Get-ScheduledTask IDS-*"
Write-Host "     Arrancar ya:       Start-ScheduledTask -TaskName 'IDS-Observacion-C3'"
Write-Host "     Detener:           Stop-ScheduledTask  -TaskName 'IDS-Observacion-C3'"
Write-Host "     Estado en vivo:    Get-Content logs_ciberseguridad\corrida_obs-c3-*.log -Tail 5 -Wait"
